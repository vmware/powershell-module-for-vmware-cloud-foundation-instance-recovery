#!/usr/bin/env bash
#
# vmsp-backup-sftp-to-yaml.sh
#
# From SFTP settings (and optional cluster actions) through downloading the
# VMSP component backup blob, decrypting it, extracting the Velero archive, and
# emitting selected Kubernetes resources as YAML.
#
# YAML export behavior (from the extracted Velero tree):
#   (1) Writes vmsp-platform.yaml and ingress-{fleet,instance,platform}-tls-ndc.yaml when present
#       (looks under resources/.../vmsp-platform/, including v1-preferredversion paths).
#   (2) If the archive contains standard ingress-*-tls Secret JSON, writes matching ingress-*-tls.yaml.
#   (3) If plain ingress-*-tls are absent but *-tls-ndc JSON exists, synthesizes kubernetes.io/tls
#       ingress-*-tls.yaml from NDC data (cert/key → tls.crt/tls.key), annotated as generated.
#   (4) Also writes vmsp-platform.json: a merge-patch body with just spec.values.profiles.name and
#       spec.values.cluster.worker.size from the backed-up PackageDeployment, for restoring cluster
#       size/worker size onto a freshly-redeployed cluster via:
#         kubectl patch packagedeployment vmsp-platform -n vmsp-platform --type=merge \
#           --patch-file vmsp-platform.json
#
# Requirements: bash 3.2+, openssl, tar, gzip, sshpass, sftp, python3 (PyYAML),
#               jq when using cluster (--configure-cluster, --trigger-backup,
#               auto-discover, or reading passphrase from a secret)
#
# Example — only pull YAML from an existing SFTP archive (no cluster changes):
#   export KUBECONFIG=~/Downloads/kubeconfig
#   VMSP_SFTP_PASSWORD='...' ./scripts/vmsp-backup-sftp-to-yaml.sh \
#     --kubeconfig "$KUBECONFIG" \
#     --sftp-host 10.186.82.56 --sftp-user sftpuser --sftp-dir 'sftpuser/vmsp-backups' \
#     --remote-archive 'sftpuser/vmsp-backups/vcf/backups/.../2026-04-21T14-25-51Z/2026-04-21T14-25-51Z.base.tgz' \
#     --output-dir ./backup-yaml
#
# Example — configure PackageDeployment, run a new backup, then export YAML:
#   VMSP_SFTP_PASSWORD='...' ./scripts/vmsp-backup-sftp-to-yaml.sh \
#     --kubeconfig "$KUBECONFIG" --configure-cluster --trigger-backup \
#     --sftp-host 10.186.82.56 --sftp-user sftpuser --sftp-dir 'sftpuser/vmsp-backups' \
#     --output-dir ./backup-yaml
#
# Security: prefer VMSP_SFTP_PASSWORD and VMSP_ENCRYPTION_PASSPHRASE env vars;
#           command-line passwords may be visible to other local users (ps).

set -euo pipefail

SCRIPT_NAME=$(basename "$0")

NAMESPACE="${VMSP_NAMESPACE:-vmsp-platform}"
PACKAGEDEPLOYMENT="${VMSP_PACKAGEDEPLOYMENT:-vmsp-platform}"
SFTP_PORT="${VMSP_SFTP_PORT:-22}"

KUBECONFIG_PATH="${KUBECONFIG:-}"
SFTP_HOST=""
SFTP_USER=""
SFTP_PASSWORD="${VMSP_SFTP_PASSWORD:-}"
SFTP_DIR=""
REMOTE_ARCHIVE=""

CONFIGURE_CLUSTER=false
TRIGGER_BACKUP=false
DISCOVER_LATEST=true

OUTPUT_DIR=""
WORK_DIR=""
PASSPHRASE="${VMSP_ENCRYPTION_PASSPHRASE:-}"
ENCRYPTION_SECRET="${VMSP_ENCRYPTION_SECRET:-encryption-passphrase-secret}"
ENCRYPTION_SECRET_KEY="${VMSP_ENCRYPTION_SECRET_KEY:-encryptionPassphrase}"

SFTP_PASSWORD_SECRET_NAME="${VMSP_SFTP_PASSWORD_SECRET:-sftp-password-secret}"
SFTP_PASSWORD_SECRET_KEY="${VMSP_SFTP_PASSWORD_SECRET_KEY:-sftpPassword}"

# kubectl apply: ensure SFTP password exists in cluster when configuring/triggering
UPDATE_SFTP_SECRET=false

die() { echo "$SCRIPT_NAME: $*" >&2; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat >&2 <<EOF
Usage:
  $SCRIPT_NAME [options]

Cluster / kube:
  --kubeconfig PATH          Kubeconfig file (or set KUBECONFIG)
  --namespace NS             Namespace (default: $NAMESPACE)
  --packagedeployment NAME    PackageDeployment name (default: $PACKAGEDEPLOYMENT)

SFTP (required for download unless --remote-archive is a local file):
  --sftp-host HOST
  --sftp-port PORT           (default: $SFTP_PORT)
  --sftp-user USER
  --sftp-password PASS       (or env VMSP_SFTP_PASSWORD)
  --sftp-dir PATH            Remote root for backups, e.g. sftpuser/vmsp-backups

Optional archive path:
  --remote-archive PATH      Full SFTP path to *.base.tgz (no leading /), or a local file
  --no-discover              Do not auto-pick latest backup from SFTP (requires --remote-archive)

Cluster-side SFTP wiring (updates PackageDeployment + optional secret):
  --configure-cluster        Patch spec.values.sftp on PackageDeployment
  --update-sftp-secret       kubectl apply password into $SFTP_PASSWORD_SECRET_NAME
  --trigger-backup           Create BackupComponent Task and wait for Succeeded

Encryption:
  --passphrase STR           Or env VMSP_ENCRYPTION_PASSPHRASE; else read from secret \$ENCRYPTION_SECRET

Output:
  --output-dir DIR           Write YAML here (default: temp dir, printed at end)
  --work-dir DIR             Temp scratch (default: mktemp -d under /tmp)

Exports (under output dir):
  vmsp-platform.yaml              PackageDeployment (if present in backup)
  vmsp-platform.json              Merge-patch body: spec.values.profiles.name and
                                  spec.values.cluster.worker.size (if present in backup)
  ingress-*-tls-ndc.yaml          NDC mirror secrets from backup (if present)
  ingress-*-tls.yaml            Standard TLS secrets; from backup if present, else
                                  synthesized from *-tls-ndc (same cert/key material)
EOF
}

require() { have_cmd "$1" || die "missing required command: $1"; }

sftp_batch() {
  local pass="$1"
  shift
  export SSHPASS="$pass"
  printf '%s\n' "$@" | sshpass -e sftp \
    -oBatchMode=no \
    -oPreferredAuthentications=password \
    -oPubkeyAuthentication=no \
    -oStrictHostKeyChecking="${SFTP_STRICT_HOSTKEY:-no}" \
    -P "${SFTP_PORT}" \
    "${SFTP_USER}@${SFTP_HOST}"
}

# sftp (without -b) stays interactive: a failing per-command action (get/cd/ls) prints an
# error but does not make the sftp process exit non-zero, and -b forces BatchMode=yes on the
# underlying ssh session which breaks sshpass-based password auth. So failures must be detected
# by scanning the transcript for sftp's own error text, not by trusting the exit code.
sftp_check_output() {
  local tmp="$1"
  grep -Eiq "Couldn.t|Can.t |not found|no such file|not a regular file|permission denied|connection (closed|refused)|Received message too long|Fatal error" "$tmp"
}

sftp_list_names() {
  # Usage: sftp_list_names REMOTE_DIR  (prints one name per line)
  local rdir="$1"
  local pass="$2"
  local tmp
  tmp=$(mktemp)
  # shellcheck disable=SC2068
  sftp_batch "$pass" "cd ${rdir}" 'ls -1' 'bye' >"$tmp" 2>&1
  if sftp_check_output "$tmp"; then cat "$tmp" >&2; rm -f "$tmp"; return 1; fi
  # Drop noise lines
  # Note: avoid apostrophes in awk regex (breaks bash single-quoted string)
  awk '/^sftp>/ {next} /^Connected to / {next} /^Fetching / {next} /^Uploading / {next} /^Removing / {next} /^Changing mode / {next} /^Remote working directory/ {next} /^Couldn.t / {print > "/dev/stderr"; exit 1} /^Can.t / {print > "/dev/stderr"; exit 1} NF {print}' "$tmp" | sed '/^$/d'
  rm -f "$tmp"
}

sftp_download() {
  local remote_path="$1"
  local local_path="$2"
  local pass="$3"
  local tmp
  tmp=$(mktemp)
  sftp_batch "$pass" "get ${remote_path} ${local_path}" 'bye' >"$tmp" 2>&1
  if sftp_check_output "$tmp" || [[ ! -s "$local_path" ]]; then
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}

kubectl_with() {
  kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"
}

discover_remote_archive() {
  # Sets REMOTE_ARCHIVE to path like: <sftp-dir>/vcf/backups/<cid>/<ver>/vsp/<cid>/<ver>/<stamp>/<stamp>.base.tgz
  local pass="$1"

  local cid ver
  cid=$(kubectl_with get packagedeployment "$PACKAGEDEPLOYMENT" -n "$NAMESPACE" -o json | jq -r '.spec.values.cluster.id // empty')
  ver=$(kubectl_with get packagedeployment "$PACKAGEDEPLOYMENT" -n "$NAMESPACE" -o json | jq -r '.metadata.labels["component.vmsp.vmware.com/version"] // empty')
  [[ -n "$cid" && -n "$ver" ]] || die "could not read cluster id / component version from PackageDeployment"

  local base="${SFTP_DIR}/vcf/backups/${cid}/${ver}/vsp/${cid}/${ver}"
  local stamps=()
  local line
  while IFS= read -r line; do
    stamps+=("$line")
  done < <(sftp_list_names "$base" "$pass" | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' || true)

  [[ ${#stamps[@]} -gt 0 ]] || die "no backup timestamp directories under SFTP: $base"

  local latest_stamp
  latest_stamp=$(printf '%s\n' "${stamps[@]}" | sort -V | tail -n1)

  local inner=()
  while IFS= read -r line; do
    inner+=("$line")
  done < <(sftp_list_names "${base}/${latest_stamp}" "$pass" || true)

  local tgz=""
  for line in "${inner[@]}"; do
    if [[ "$line" == *.base.tgz ]]; then
      tgz="$line"
      break
    fi
  done
  [[ -n "$tgz" ]] || die "no *.base.tgz under ${base}/${latest_stamp}"

  REMOTE_ARCHIVE="${base}/${latest_stamp}/${tgz}"
  echo "$SCRIPT_NAME: discovered archive: $REMOTE_ARCHIVE"
}

ensure_pyyaml() {
  python3 - <<'PY' 2>/dev/null && return 0
import yaml  # noqa: F401
PY
  python3 -m pip install --user -q pyyaml || die "install PyYAML: python3 -m pip install --user pyyaml"
}

json_to_yaml_dir() {
  local velero_inner="$1"
  local out="$2"
  mkdir -p "$out"
  python3 - "$velero_inner" "$out" <<'PY'
import json
import sys
import pathlib
from typing import Optional

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

velero_inner, out = sys.argv[1], sys.argv[2]
base = pathlib.Path(velero_inner)
out_dir = pathlib.Path(out)


def strip_meta(o):
    if not isinstance(o, dict):
        return o
    md = o.get("metadata") or {}
    for k in ("managedFields", "resourceVersion", "uid", "creationTimestamp"):
        md.pop(k, None)
    o["metadata"] = md
    return o


def resolve_secret_json(stem: str) -> Optional[pathlib.Path]:
    """Velero may store under secrets/namespaces/... or secrets/v1-preferredversion/..."""
    for pat in (
        base / "resources" / "secrets" / "namespaces" / "vmsp-platform" / f"{stem}.json",
        base / "resources" / "secrets" / "v1-preferredversion" / "namespaces" / "vmsp-platform" / f"{stem}.json",
    ):
        if pat.is_file():
            return pat
    return None


def resolve_packagedeployment_json() -> Optional[pathlib.Path]:
    for pat in (
        base / "resources" / "packagedeployments.releases.vmsp.vmware.com" / "namespaces" / "vmsp-platform" / "vmsp-platform.json",
        base / "resources" / "packagedeployments.releases.vmsp.vmware.com" / "v1-preferredversion" / "namespaces" / "vmsp-platform" / "vmsp-platform.json",
    ):
        if pat.is_file():
            return pat
    return None


def synthesize_tls_from_ndc(ndc_path: pathlib.Path, plain_stem: str) -> dict:
    """
    Build a kubernetes.io/tls Secret from an NDC Opaque secret JSON.
    NDC uses data keys cert, key, ca (same as object-backup-restore / ndc controller).
    """
    with open(ndc_path) as f:
        ndc = json.load(f)
    data = ndc.get("data") or {}
    cert_b64 = data.get("cert") or data.get("tls.crt")
    key_b64 = data.get("key") or data.get("tls.key")
    if not cert_b64 or not key_b64:
        raise ValueError(
            f"NDC secret {ndc_path} has no cert/key (or tls.crt/tls.key) in .data; cannot synthesize {plain_stem}"
        )
    ns = (ndc.get("metadata") or {}).get("namespace", "vmsp-platform")
    md = {
        "name": plain_stem,
        "namespace": ns,
        "annotations": {
            "vmsp.vmware.com/generated-from-backup": ndc_path.name.replace(".json", ""),
        },
    }
    ndc_labels = (ndc.get("metadata") or {}).get("labels") or {}
    labels = {k: v for k, v in ndc_labels.items() if k != "backup.vmsp.vmware.com/skip-restore"}
    if labels:
        md["labels"] = labels
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": md,
        "type": "kubernetes.io/tls",
        "data": {
            "tls.crt": cert_b64,
            "tls.key": key_b64,
        },
    }


p = resolve_packagedeployment_json()
if p is not None:
    with open(p) as f:
        obj = json.load(f)
    obj = strip_meta(obj)
    dst = out_dir / (p.stem + ".yaml")
    with open(dst, "w") as f:
        yaml.safe_dump(obj, f, default_flow_style=False, sort_keys=False)
    print(dst)

    values = (obj.get("spec") or {}).get("values") or {}
    patch_values = {}
    profile_name = (values.get("profiles") or {}).get("name")
    if profile_name is not None:
        patch_values.setdefault("profiles", {})["name"] = profile_name
    worker_size = ((values.get("cluster") or {}).get("worker") or {}).get("size")
    if worker_size is not None:
        patch_values.setdefault("cluster", {}).setdefault("worker", {})["size"] = worker_size
    if patch_values:
        patch_dst = out_dir / "vmsp-platform.json"
        with open(patch_dst, "w") as f:
            json.dump({"spec": {"values": patch_values}}, f, indent=2)
            f.write("\n")
        print(patch_dst)

for ndc_stem in ("ingress-fleet-tls-ndc", "ingress-instance-tls-ndc", "ingress-platform-tls-ndc"):
    p = resolve_secret_json(ndc_stem)
    if p is None:
        continue
    with open(p) as f:
        obj = json.load(f)
    obj = strip_meta(obj)
    dst = out_dir / (p.stem + ".yaml")
    with open(dst, "w") as f:
        yaml.safe_dump(obj, f, default_flow_style=False, sort_keys=False)
    print(dst)

# Plain ingress-*-tls (standard kubernetes.io/tls) when present in backup
for stem in ("ingress-fleet-tls", "ingress-instance-tls", "ingress-platform-tls"):
    pat = resolve_secret_json(stem)
    if pat is not None:
        with open(pat) as f:
            obj = json.load(f)
        obj = strip_meta(obj)
        dst = out_dir / f"{stem}.yaml"
        with open(dst, "w") as f:
            yaml.safe_dump(obj, f, default_flow_style=False, sort_keys=False)
        print(dst)

# Synthesize ingress-*-tls from *-tls-ndc when plain secret was not in the Velero archive
for plain_stem, ndc_stem in (
    ("ingress-fleet-tls", "ingress-fleet-tls-ndc"),
    ("ingress-instance-tls", "ingress-instance-tls-ndc"),
    ("ingress-platform-tls", "ingress-platform-tls-ndc"),
):
    plain_yaml = out_dir / f"{plain_stem}.yaml"
    if plain_yaml.is_file():
        continue
    ndc_json = resolve_secret_json(ndc_stem)
    if ndc_json is None:
        continue
    try:
        syn = synthesize_tls_from_ndc(ndc_json, plain_stem)
        syn = strip_meta(syn)
    except ValueError as e:
        print(f"WARN: {e}", file=sys.stderr)
        continue
    with open(plain_yaml, "w") as f:
        yaml.safe_dump(syn, f, default_flow_style=False, sort_keys=False)
    print(plain_yaml)
PY
}

create_sftp_password_secret_in_cluster() {
  local ns="$1"
  kubectl_with create secret generic "$SFTP_PASSWORD_SECRET_NAME" -n "$ns" \
    --from-literal="$SFTP_PASSWORD_SECRET_KEY=$SFTP_PASSWORD" \
    --dry-run=client -o yaml | kubectl_with apply -f -
}

patch_packagedeployment_sftp() {
  kubectl_with patch packagedeployment "$PACKAGEDEPLOYMENT" -n "$NAMESPACE" --type merge -p "$(
    jq -n \
      --arg host "$SFTP_HOST" \
      --arg user "$SFTP_USER" \
      --arg dir "$SFTP_DIR" \
      --arg port "$SFTP_PORT" \
      '{spec:{values:{sftp:{host:$host,username:$user,directory:$dir,port:$port}}}}'
  )"
}

trigger_component_backup_task() {
  local cid
  cid=$(kubectl_with get packagedeployment "$PACKAGEDEPLOYMENT" -n "$NAMESPACE" -o json | jq -r '.spec.values.cluster.id // empty')
  [[ -n "$cid" ]] || die "cluster id not found on PackageDeployment"

  local ts tid name secret
  ts=$(date +%s)
  tid="manual-backup-${ts}"
  name="component-backup-${tid}"
  secret="$name"

  kubectl_with create secret generic "$secret" -n "$NAMESPACE" \
    --from-literal=action=backup \
    --from-literal=apidata='{}' \
    --dry-run=client -o yaml | kubectl_with label --local -f - \
    "task.workflow.vmsp.vmware.com/tracking-id=${tid}" \
    "workflow.vmsp.vmware.com/replicate-to-namespace=${NAMESPACE}" \
    -o yaml --dry-run=client | kubectl_with apply -f -

  kubectl_with apply -f - <<EOF
apiVersion: workflow.vmsp.vmware.com/v1alpha1
kind: Task
metadata:
  name: ${name}
  namespace: ${NAMESPACE}
  labels:
    task.workflow.vmsp.vmware.com/tracking-id: "${tid}"
spec:
  type: com.vmware.vcfms.task.BackupComponent
  trackingId: "${tid}"
  workflowTemplateRef:
    name: component-backup
    namespace: ${NAMESPACE}
  componentInstanceRef:
    name: ${cid}
    namespace: ${NAMESPACE}
  resource:
    componentId: ${cid}
  secretRef:
    name: ${secret}
    namespace: ${NAMESPACE}
  options:
    precheck: true
    precheckOnly: false
    syntheticCheck: true
    syntheticCheckOnly: false
EOF

  echo "$SCRIPT_NAME: waiting for Task $name ..."
  local i phase=""
  for i in $(seq 1 240); do
    phase=$(kubectl_with get task "$name" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    if [[ "$phase" == "Succeeded" ]]; then
      echo "$SCRIPT_NAME: backup task succeeded."
      return 0
    fi
    if [[ "$phase" == "Failed" ]]; then
      kubectl_with get task "$name" -n "$NAMESPACE" -o yaml | sed -n '/^status:/,$p' | head -80 >&2
      die "backup task failed: $name"
    fi
    sleep 15
  done
  die "timeout waiting for Task $name (last phase: ${phase:-unknown})"
}

resolve_passphrase_from_cluster() {
  [[ -n "$KUBECONFIG_PATH" && -r "$KUBECONFIG_PATH" ]] || die "kubeconfig required to read encryption passphrase secret (set --kubeconfig or VMSP_ENCRYPTION_PASSPHRASE)"
  kubectl_with get secret "$ENCRYPTION_SECRET" -n "$NAMESPACE" -o "jsonpath={.data.${ENCRYPTION_SECRET_KEY}}" | base64 -d
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --kubeconfig)
        KUBECONFIG_PATH="$2"; shift 2 ;;
      --namespace)
        NAMESPACE="$2"; shift 2 ;;
      --packagedeployment)
        PACKAGEDEPLOYMENT="$2"; shift 2 ;;
      --sftp-host)
        SFTP_HOST="$2"; shift 2 ;;
      --sftp-port)
        SFTP_PORT="$2"; shift 2 ;;
      --sftp-user)
        SFTP_USER="$2"; shift 2 ;;
      --sftp-password)
        SFTP_PASSWORD="$2"; shift 2 ;;
      --sftp-dir)
        SFTP_DIR="$2"; shift 2 ;;
      --remote-archive)
        REMOTE_ARCHIVE="$2"; DISCOVER_LATEST=false; shift 2 ;;
      --no-discover)
        DISCOVER_LATEST=false; shift ;;
      --configure-cluster)
        CONFIGURE_CLUSTER=true; shift ;;
      --trigger-backup)
        TRIGGER_BACKUP=true; shift ;;
      --update-sftp-secret)
        UPDATE_SFTP_SECRET=true; shift ;;
      --passphrase)
        PASSPHRASE="$2"; shift 2 ;;
      --encryption-secret)
        ENCRYPTION_SECRET="$2"; shift 2 ;;
      --output-dir)
        OUTPUT_DIR="$2"; shift 2 ;;
      --work-dir)
        WORK_DIR="$2"; shift 2 ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        die "unknown argument: $1" ;;
    esac
  done

  require openssl
  require tar
  require sshpass
  require python3

  [[ -n "$KUBECONFIG_PATH" ]] || KUBECONFIG_PATH="${KUBECONFIG:-}"

  local need_kubectl=false
  if [[ "$CONFIGURE_CLUSTER" == true || "$TRIGGER_BACKUP" == true || "$DISCOVER_LATEST" == true ]]; then
    need_kubectl=true
  fi
  if [[ -z "${PASSPHRASE:-}" ]]; then
    need_kubectl=true
  fi
  if [[ "$need_kubectl" == true ]]; then
    require kubectl
    require jq
    [[ -n "$KUBECONFIG_PATH" && -r "$KUBECONFIG_PATH" ]] || die "set --kubeconfig or KUBECONFIG to a readable file"
    export KUBECONFIG="$KUBECONFIG_PATH"
  fi

  local use_sftp_download=true
  if [[ -n "$REMOTE_ARCHIVE" && -f "$REMOTE_ARCHIVE" ]]; then
    use_sftp_download=false
  fi
  if [[ "$use_sftp_download" == true ]]; then
    [[ -n "$SFTP_HOST" ]] || die "--sftp-host is required (unless --remote-archive points at a local file)"
    [[ -n "$SFTP_USER" ]] || die "--sftp-user is required (unless --remote-archive points at a local file)"
    [[ -n "$SFTP_DIR" ]] || die "--sftp-dir is required (e.g. sftpuser/vmsp-backups)"
    [[ -n "$SFTP_PASSWORD" ]] || die "set --sftp-password or VMSP_SFTP_PASSWORD"
  fi

  if [[ -z "$WORK_DIR" ]]; then
    WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/vmsp-backup.XXXXXX")
  else
    mkdir -p "$WORK_DIR"
  fi
  trap '[[ "${KEEP_WORK:-0}" != 1 ]] && rm -rf "${WORK_DIR:-}"' EXIT

  if [[ "$UPDATE_SFTP_SECRET" == true || "$CONFIGURE_CLUSTER" == true || "$TRIGGER_BACKUP" == true ]]; then
    create_sftp_password_secret_in_cluster "$NAMESPACE"
  fi
  if [[ "$CONFIGURE_CLUSTER" == true ]]; then
    patch_packagedeployment_sftp
    kubectl_with annotate helmrelease vmsp-backup -n "$NAMESPACE" "reconcile.fluxcd.io/requestedAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" --overwrite 2>/dev/null || true
    echo "$SCRIPT_NAME: PackageDeployment SFTP values patched; waiting for global-config / Helm to settle (15s)..."
    sleep 15
  fi
  if [[ "$TRIGGER_BACKUP" == true ]]; then
    trigger_component_backup_task
  fi

  local local_blob blob_name
  if [[ -n "$REMOTE_ARCHIVE" && -f "$REMOTE_ARCHIVE" ]]; then
    local_blob="$REMOTE_ARCHIVE"
    echo "$SCRIPT_NAME: using local file: $local_blob"
  else
    if [[ -z "$REMOTE_ARCHIVE" && "$DISCOVER_LATEST" == true ]]; then
      discover_remote_archive "$SFTP_PASSWORD"
    fi
    [[ -n "$REMOTE_ARCHIVE" ]] || die "set --remote-archive or ensure discover path works"

    blob_name=$(basename "$REMOTE_ARCHIVE")
    local_blob="${WORK_DIR}/${blob_name}"
    echo "$SCRIPT_NAME: downloading sftp:${REMOTE_ARCHIVE} -> $local_blob"
    sftp_download "$REMOTE_ARCHIVE" "$local_blob" "$SFTP_PASSWORD"
  fi

  [[ -f "$local_blob" ]] || die "backup blob not found: $local_blob"

  if [[ -z "$PASSPHRASE" ]]; then
    PASSPHRASE=$(resolve_passphrase_from_cluster)
  fi
  [[ -n "$PASSPHRASE" ]] || die "encryption passphrase empty (set --passphrase or ensure secret $ENCRYPTION_SECRET)"

  local outer="${WORK_DIR}/decoded.tgz"
  export ENCRYPTION_PASSPHRASE="$PASSPHRASE"
  openssl enc -d -aes-256-cbc -pbkdf2 -pass env:ENCRYPTION_PASSPHRASE -in "$local_blob" -out "$outer"

  local outer_root="${WORK_DIR}/outer"
  mkdir -p "$outer_root"
  tar -xzf "$outer" -C "$outer_root"

  local inner
  inner=$(find "$outer_root" -type f -name '*-vsp-*.tar.gz' | head -n1 || true)
  [[ -n "$inner" ]] || die "could not find inner Velero *-vsp-*.tar.gz under extracted backup"

  local velero_inner="${WORK_DIR}/velero-inner"
  mkdir -p "$velero_inner"
  tar -xzf "$inner" -C "$velero_inner"

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/vmsp-yaml-out.XXXXXX")
  fi
  mkdir -p "$OUTPUT_DIR"

  ensure_pyyaml
  json_to_yaml_dir "$velero_inner" "$OUTPUT_DIR"

  echo ""
  echo "$SCRIPT_NAME: YAML written under: $OUTPUT_DIR"
  ls -la "$OUTPUT_DIR"
}

main "$@"

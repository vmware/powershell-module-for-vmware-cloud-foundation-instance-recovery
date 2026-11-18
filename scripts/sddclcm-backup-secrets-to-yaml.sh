#!/usr/bin/env bash
#
# sddclcm-backup-secrets-to-yaml.sh
#
# From SFTP settings (or a local backup blob) through downloading the SDDC LCM
# component backup archive, decrypting it (if encrypted), extracting the
# Velero archive, and pulling out the fixed set of vcf-sddc-lcm identity
# secrets needed to re-home VSP/VCFA/Ops/Ops-Networks/Salt-RaaS service
# accounts during DR (see update_vcfa_registration.sh /
# create_vcfa_registration.sh):
#
#   vcf-iam-ops-admin.json
#   vcf-iam-ops-networks-admin.json
#   vcf-iam-salt-raas-admin.json
#   vcf-iam-vcfa-admin.json
#   vcf-iam-vsp-admin.json
#
# These are extracted as-is (valid Secret JSON manifests straight from the
# Velero backup, under resources/secrets/namespaces/vcf-sddc-lcm/) - no YAML
# conversion - so they can be applied directly:
#   kubectl apply -f <output-dir>/vcf-iam-vcfa-admin.json
#
# Requirements: bash 3.2+, tar, gzip, sshpass, sftp, jq (only when
#               auto-discovering the latest archive or reading the
#               passphrase from a cluster secret). openssl is only required
#               if the backup blob is actually encrypted (auto-detected).
#
# Example — local backup blob, unencrypted or passphrase given explicitly:
#   ./scripts/sddclcm-backup-secrets-to-yaml.sh \
#     --remote-archive /path/to/2026-09-10T18-19-00Z.backup.tgz \
#     --output-dir ./sddclcm-secrets
#
# Example — pull latest archive over SFTP, decrypting with a passphrase read
# from a cluster secret:
#   export KUBECONFIG=~/Downloads/kubeconfig
#   SDDCLCM_SFTP_PASSWORD='...' ./scripts/sddclcm-backup-secrets-to-yaml.sh \
#     --kubeconfig "$KUBECONFIG" \
#     --sftp-host 10.186.82.56 --sftp-user sftpuser --sftp-dir 'sftpuser/vmsp-backups' \
#     --sftp-remote-dir 'sftpuser/vmsp-backups/vcf/backups/sddclcm-mgmt/9.0.1.0' \
#     --output-dir ./sddclcm-secrets
#
# Security: prefer SDDCLCM_SFTP_PASSWORD and SDDCLCM_ENCRYPTION_PASSPHRASE
#           env vars; command-line passwords may be visible to other local
#           users (ps).

set -euo pipefail

SCRIPT_NAME=$(basename "$0")

# The 5 identity secrets this script extracts, and the fixed namespace (as
# recorded inside the Velero backup, not necessarily the namespace on the
# live cluster you're restoring onto) they live under.
SECRET_NAMES=(
  "vcf-iam-ops-admin"
  "vcf-iam-ops-networks-admin"
  "vcf-iam-salt-raas-admin"
  "vcf-iam-vcfa-admin"
  "vcf-iam-vsp-admin"
)
# Namespace(s) to look for the 5 secrets under inside the extracted backup
# (resources/secrets/namespaces/<ns>/<name>.json). "vcf-sddc-lcm" is the
# namespace name on a *shared fleet* cluster (e.g. inst5 in our DR work);
# "vmsp-platform" is the namespace convention for SDDC LCM's own dedicated
# VMSP-hosted cluster (like every other single-tenant VMSP cluster - VCFA's
# own cluster, etc.). Both are tried, in this order, unless overridden.
BACKUP_NAMESPACES=("vmsp-platform" "vcf-sddc-lcm")

# Namespace to read the encryption passphrase secret from on the *live*
# cluster (only used when --kubeconfig/KUBECONFIG is set and --passphrase
# isn't given directly) - same "vmsp-platform vs vcf-sddc-lcm" ambiguity
# applies here, so this is also just a default, override with --namespace.
NAMESPACE="${SDDCLCM_NAMESPACE:-vmsp-platform}"
SFTP_PORT="${SDDCLCM_SFTP_PORT:-22}"

KUBECONFIG_PATH="${KUBECONFIG:-}"
SFTP_HOST=""
SFTP_USER=""
SFTP_PASSWORD="${SDDCLCM_SFTP_PASSWORD:-}"
SFTP_REMOTE_DIR=""
REMOTE_ARCHIVE=""
DISCOVER_LATEST=true

OUTPUT_DIR=""
WORK_DIR=""
PASSPHRASE="${SDDCLCM_ENCRYPTION_PASSPHRASE:-}"
ENCRYPTION_SECRET="${SDDCLCM_ENCRYPTION_SECRET:-encryption-passphrase-secret}"
ENCRYPTION_SECRET_KEY="${SDDCLCM_ENCRYPTION_SECRET_KEY:-encryptionPassphrase}"

# Glob (relative to the extracted outer archive) used to locate the inner
# Velero *.tar.gz. Override with --inner-archive-glob if your backup names
# it differently.
INNER_ARCHIVE_GLOB="${SDDCLCM_INNER_ARCHIVE_GLOB:-}"

die() { echo "$SCRIPT_NAME: $*" >&2; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat >&2 <<EOF
Usage:
  $SCRIPT_NAME [options]

Cluster / kube (only needed for --sftp-* auto-discovery or reading the
encryption passphrase from a secret):
  --kubeconfig PATH          Kubeconfig file (or set KUBECONFIG)
  --namespace NS             Namespace to read the encryption secret from
                              on the live cluster (default: $NAMESPACE)
  --backup-namespace NS      Force a single namespace to look for the 5
                              secrets under inside the backup, instead of
                              trying vmsp-platform then vcf-sddc-lcm

SFTP (required for download unless --remote-archive is a local file):
  --sftp-host HOST
  --sftp-port PORT           (default: $SFTP_PORT)
  --sftp-user USER
  --sftp-password PASS       (or env SDDCLCM_SFTP_PASSWORD)
  --sftp-remote-dir PATH     Remote dir holding backup timestamp dirs, e.g.
                              sftpuser/vmsp-backups/vcf/backups/sddclcm-mgmt/9.0.1.0

Archive:
  --remote-archive PATH      Full SFTP path to *.backup.tgz (no leading /),
                              or a local file
  --no-discover              Do not auto-pick latest backup from SFTP
                              (requires --remote-archive)
  --inner-archive-glob GLOB  Glob (under extracted outer archive) to find the
                              inner Velero *.tar.gz. Default: auto-detect
                              (prefers a name containing "sddc"; otherwise
                              the sole *.tar.gz found).

Encryption (only used if the blob is actually encrypted - auto-detected by
gzip magic bytes; skipped entirely for a plain, unencrypted backup blob):
  --passphrase STR           Or env SDDCLCM_ENCRYPTION_PASSPHRASE; else read
                              from secret \$ENCRYPTION_SECRET on the cluster
  --encryption-secret NAME   (default: $ENCRYPTION_SECRET)

Output:
  --output-dir DIR           Write the 5 secret JSON files here (default:
                              temp dir, printed at end)
  --work-dir DIR             Temp scratch (default: mktemp -d under /tmp)

Extracts (under output dir), as-is Secret JSON manifests ready for
'kubectl apply -f':
$(printf '  %s.json\n' "${SECRET_NAMES[@]}")
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

# Authentication failure is not a "this path/file doesn't exist" condition -
# it's unrecoverable for the whole run, and swallowing it as an empty listing
# (as a generic sftp_check_output failure would, once piped through
# `... || true` at call sites) produces a very misleading "no backup
# directories found" error instead of the real cause. Abort immediately with
# a clear message instead.
sftp_die_on_auth_failure() {
  local tmp="$1"
  if grep -Eiq "permission denied|authentication failed" "$tmp"; then
    cat "$tmp" >&2
    rm -f "$tmp"
    die "SFTP authentication failed for ${SFTP_USER}@${SFTP_HOST} - check --sftp-user/--sftp-password (SDDCLCM_SFTP_PASSWORD)"
  fi
}

sftp_list_names() {
  # Usage: sftp_list_names REMOTE_DIR PASSWORD  (prints one name per line)
  local rdir="$1"
  local pass="$2"
  local tmp
  tmp=$(mktemp)
  sftp_batch "$pass" "cd ${rdir}" 'ls -1' 'bye' >"$tmp" 2>&1
  sftp_die_on_auth_failure "$tmp"
  if sftp_check_output "$tmp"; then cat "$tmp" >&2; rm -f "$tmp"; return 1; fi
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
  sftp_die_on_auth_failure "$tmp"
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
  # $SFTP_REMOTE_DIR may point at either:
  #   (a) a leaf directory that already directly contains the archive
  #       (<stamp>.backup.tgz / <stamp>.base.tgz) plus manifest.json, or
  #   (b) a parent directory containing multiple <stamp>/ subdirectories,
  #       each holding one archive - in which case pick the latest <stamp>.
  # Try (a) first: an entry name matching *.backup.tgz/*.base.tgz at this
  # level is unambiguous (an actual timestamp *subdirectory* name never has
  # a .tgz suffix), so this can't misfire the way a bare timestamp-prefix
  # match against subdirectory names can.
  local pass="$1"

  local top=()
  local line
  while IFS= read -r line; do
    top+=("$line")
  done < <(sftp_list_names "$SFTP_REMOTE_DIR" "$pass" || true)

  local tgz=""
  for line in "${top[@]}"; do
    if [[ "$line" == *.backup.tgz || "$line" == *.base.tgz ]]; then
      tgz="$line"
      break
    fi
  done
  if [[ -n "$tgz" ]]; then
    REMOTE_ARCHIVE="${SFTP_REMOTE_DIR}/${tgz}"
    echo "$SCRIPT_NAME: discovered archive (leaf dir): $REMOTE_ARCHIVE"
    return 0
  fi

  # (b) - descend into the latest <stamp>/ subdirectory. Only entries that
  # are actual timestamp *directory* names get here (no .tgz found above),
  # but guard against any stray file that happens to share the timestamp
  # prefix by requiring the match not end in a known archive extension.
  local stamps=()
  for line in "${top[@]}"; do
    if [[ "$line" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] && [[ "$line" != *.tgz && "$line" != *.json ]]; then
      stamps+=("$line")
    fi
  done

  [[ ${#stamps[@]} -gt 0 ]] || die "no backup archive directly under, nor timestamp subdirectories under, SFTP: $SFTP_REMOTE_DIR"

  local latest_stamp
  latest_stamp=$(printf '%s\n' "${stamps[@]}" | sort -V | tail -n1)

  local inner=()
  while IFS= read -r line; do
    inner+=("$line")
  done < <(sftp_list_names "${SFTP_REMOTE_DIR}/${latest_stamp}" "$pass" || true)

  tgz=""
  for line in "${inner[@]}"; do
    if [[ "$line" == *.backup.tgz || "$line" == *.base.tgz ]]; then
      tgz="$line"
      break
    fi
  done
  [[ -n "$tgz" ]] || die "no *.backup.tgz/*.base.tgz under ${SFTP_REMOTE_DIR}/${latest_stamp}"

  REMOTE_ARCHIVE="${SFTP_REMOTE_DIR}/${latest_stamp}/${tgz}"
  echo "$SCRIPT_NAME: discovered archive: $REMOTE_ARCHIVE"
}

resolve_passphrase_from_cluster() {
  [[ -n "$KUBECONFIG_PATH" && -r "$KUBECONFIG_PATH" ]] || die "kubeconfig required to read encryption passphrase secret (set --kubeconfig or SDDCLCM_ENCRYPTION_PASSPHRASE)"
  kubectl_with get secret "$ENCRYPTION_SECRET" -n "$NAMESPACE" -o "jsonpath={.data.${ENCRYPTION_SECRET_KEY}}" | base64 -d
}

# Backups may or may not be openssl-encrypted (observed in the wild: some
# component backup blobs are extracted "without decryption"). Detect by
# checking for gzip magic bytes (1f 8b) - a plain .tgz is valid gzip; an
# openssl-encrypted blob is not.
is_gzip() {
  local f="$1"
  [[ "$(head -c2 "$f" | od -An -tx1 | tr -d ' \n')" == "1f8b" ]]
}

find_inner_archive() {
  local outer_root="$1"
  local found=""

  if [[ -n "$INNER_ARCHIVE_GLOB" ]]; then
    found=$(find "$outer_root" -type f -name "$INNER_ARCHIVE_GLOB" | head -n1 || true)
    [[ -n "$found" ]] || die "no file matching --inner-archive-glob '$INNER_ARCHIVE_GLOB' under extracted backup"
    echo "$found"
    return 0
  fi

  # Prefer a *.tar.gz whose name suggests the SDDC LCM component specifically,
  # since a mgmt-cluster backup blob can contain archives for multiple
  # components.
  found=$(find "$outer_root" -type f \( -iname '*sddc-lcm*.tar.gz' -o -iname '*sddclcm*.tar.gz' \) | head -n1 || true)
  if [[ -n "$found" ]]; then
    echo "$found"
    return 0
  fi

  # Fall back to the sole *.tar.gz present.
  local all=()
  while IFS= read -r found; do all+=("$found"); done < <(find "$outer_root" -type f -name '*.tar.gz')
  if [[ ${#all[@]} -eq 1 ]]; then
    echo "${all[0]}"
    return 0
  fi

  die "could not uniquely determine the inner Velero *.tar.gz under extracted backup (found ${#all[@]} candidates: ${all[*]:-none}); pass --inner-archive-glob to disambiguate"
}

extract_secrets() {
  local velero_inner="$1"
  local out="$2"
  mkdir -p "$out"

  local name found=false
  for name in "${SECRET_NAMES[@]}"; do
    local src="" ns
    for ns in "${BACKUP_NAMESPACES[@]}"; do
      for pat in \
        "resources/secrets/namespaces/${ns}/${name}.json" \
        "resources/secrets/v1-preferredversion/namespaces/${ns}/${name}.json"
      do
        if [[ -f "${velero_inner}/${pat}" ]]; then
          src="${velero_inner}/${pat}"
          break 2
        fi
      done
    done

    if [[ -z "$src" ]]; then
      echo "$SCRIPT_NAME: WARN not found in backup: ${name}.json (checked namespaces: ${BACKUP_NAMESPACES[*]})" >&2
      continue
    fi

    cp "$src" "${out}/${name}.json"
    echo "${out}/${name}.json (from namespace: ${ns})"
    found=true
  done

  [[ "$found" == true ]] || die "none of the 5 expected secrets were found under resources/secrets/namespaces/{${BACKUP_NAMESPACES[*]}}/ in this backup"
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --kubeconfig)
        KUBECONFIG_PATH="$2"; shift 2 ;;
      --namespace)
        NAMESPACE="$2"; shift 2 ;;
      --backup-namespace)
        BACKUP_NAMESPACES=("$2"); shift 2 ;;
      --sftp-host)
        SFTP_HOST="$2"; shift 2 ;;
      --sftp-port)
        SFTP_PORT="$2"; shift 2 ;;
      --sftp-user)
        SFTP_USER="$2"; shift 2 ;;
      --sftp-password)
        SFTP_PASSWORD="$2"; shift 2 ;;
      --sftp-remote-dir)
        SFTP_REMOTE_DIR="$2"; shift 2 ;;
      --remote-archive)
        REMOTE_ARCHIVE="$2"; DISCOVER_LATEST=false; shift 2 ;;
      --no-discover)
        DISCOVER_LATEST=false; shift ;;
      --inner-archive-glob)
        INNER_ARCHIVE_GLOB="$2"; shift 2 ;;
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

  require tar
  require sshpass

  [[ -n "$KUBECONFIG_PATH" ]] || KUBECONFIG_PATH="${KUBECONFIG:-}"

  local use_sftp_download=true
  if [[ -n "$REMOTE_ARCHIVE" && -f "$REMOTE_ARCHIVE" ]]; then
    use_sftp_download=false
  fi
  if [[ "$use_sftp_download" == true ]]; then
    require jq
    [[ -n "$SFTP_HOST" ]] || die "--sftp-host is required (unless --remote-archive points at a local file)"
    [[ -n "$SFTP_USER" ]] || die "--sftp-user is required (unless --remote-archive points at a local file)"
    [[ -n "$SFTP_REMOTE_DIR" ]] || die "--sftp-remote-dir is required (e.g. sftpuser/vmsp-backups/vcf/backups/sddclcm-mgmt/9.0.1.0)"
    [[ -n "$SFTP_PASSWORD" ]] || die "set --sftp-password or SDDCLCM_SFTP_PASSWORD"
    [[ "$DISCOVER_LATEST" == true || -n "$REMOTE_ARCHIVE" ]] || die "set --remote-archive or drop --no-discover"
  fi

  if [[ -z "$WORK_DIR" ]]; then
    WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sddclcm-backup.XXXXXX")
  else
    mkdir -p "$WORK_DIR"
  fi
  trap '[[ "${KEEP_WORK:-0}" != 1 ]] && rm -rf "${WORK_DIR:-}"' EXIT

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

  local outer="$local_blob"
  if ! is_gzip "$local_blob"; then
    echo "$SCRIPT_NAME: blob is not plain gzip - assuming it is openssl-encrypted; decrypting..."
    require openssl
    if [[ -z "$PASSPHRASE" ]]; then
      PASSPHRASE=$(resolve_passphrase_from_cluster)
    fi
    [[ -n "$PASSPHRASE" ]] || die "encryption passphrase empty (set --passphrase or ensure secret $ENCRYPTION_SECRET)"
    outer="${WORK_DIR}/decoded.tgz"
    export ENCRYPTION_PASSPHRASE="$PASSPHRASE"
    openssl enc -d -aes-256-cbc -pbkdf2 -pass env:ENCRYPTION_PASSPHRASE -in "$local_blob" -out "$outer"
  else
    echo "$SCRIPT_NAME: blob is plain gzip - extracting without decryption."
  fi

  local outer_root="${WORK_DIR}/outer"
  mkdir -p "$outer_root"
  tar -xzf "$outer" -C "$outer_root"

  local inner
  inner=$(find_inner_archive "$outer_root")
  echo "$SCRIPT_NAME: using inner Velero archive: $inner"

  local velero_inner="${WORK_DIR}/velero-inner"
  mkdir -p "$velero_inner"
  tar -xzf "$inner" -C "$velero_inner"

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sddclcm-secrets-out.XXXXXX")
  fi
  mkdir -p "$OUTPUT_DIR"

  extract_secrets "$velero_inner" "$OUTPUT_DIR"

  echo ""
  echo "$SCRIPT_NAME: secrets written under: $OUTPUT_DIR"
  ls -la "$OUTPUT_DIR"
}

main "$@"

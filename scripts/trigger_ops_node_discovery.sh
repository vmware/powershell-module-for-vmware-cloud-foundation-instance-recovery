#!/bin/bash

# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

# =============================================================================
# trigger_ops_node_discovery.sh
# DR Fix: Seed OPS Node + Trigger SDDC LCM Refresh (V1.0)
# =============================================================================
#
# After a DR failover/restore, SDDC LCM's own `node` table can end up with no
# rows for the OPS component even though the `component` row itself is
# present - which breaks SDDC LCM's node-discovery `action=refresh` (it needs
# an existing MASTER node's fqdn to know which address to (re)discover
# against; see OpsDiscoveryService.findValidOpsFqdn). This script seeds a
# minimal placeholder MASTER node row from the OPS component's own recorded
# fqdn/version, then triggers a refresh so SDDC LCM re-discovers the real,
# full node topology live from the running Ops appliance.
#
# What this script does:
#   1. SDDC LCM DB: reads the OPS component's component_id / fqdn / version.
#   2. SDDC LCM DB: inserts a MASTER node row for that component (skipped if
#      one already exists - idempotent).
#   3. Prompts for the admin@vsp.local password and acquires a bearer token
#      against this cluster's own identity endpoint.
#   4. Triggers SDDC LCM's `action=refresh` for the OPS component, executed
#      inside the sddc-build-service pod against its local API port.
#
# Prerequisites:
#   - KUBECONFIG set before running, pointing to the mgmt cluster hosting
#     this SDDC LCM (must have the vcf-sddc-lcm and vmsp-platform namespaces)
#   - jq installed
#
# Usage:
#   export KUBECONFIG=<mgmt-cluster-kubeconfig>
#   ./trigger_ops_node_discovery.sh [--dry-run]
#
# Environment:
#   VSP_ADMIN_PASSWORD   admin@vsp.local password (else prompted)
# =============================================================================

set -uo pipefail   # deliberately NOT -e: `read` returns 1 at EOF and would abort.

SDDC_NS="vcf-sddc-lcm"
SDDC_DB="vcfsddclcmdb"
PLATFORM_NS="vmsp-platform"

DRY_RUN=false
VSP_ADMIN_PASSWORD="${VSP_ADMIN_PASSWORD:-}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      echo "Usage: $0 [--dry-run]"
      echo ""
      echo "Seeds a placeholder MASTER node row for the OPS component in SDDC"
      echo "LCM's DB (if missing), then triggers SDDC LCM to refresh/rediscover"
      echo "the OPS component's real node topology from the live appliance."
      echo ""
      echo "Environment:"
      echo "  KUBECONFIG            (required) Must point at the mgmt cluster"
      echo "                        hosting this SDDC LCM."
      echo "  VSP_ADMIN_PASSWORD    admin@vsp.local password (else prompted)"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

log() { echo "  $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

[[ -n "${KUBECONFIG:-}" ]] || die "KUBECONFIG must be set, pointing at the target mgmt cluster."

# ── Helpers ───────────────────────────────────────────────────────────────────

find_primary_pod() {
  local ns=$1 prefix=$2 pod
  for pod in "${prefix}-0" "${prefix}-1" "${prefix}-2"; do
    if kubectl exec -n "$ns" "$pod" -c postgres -- \
        psql -U postgres -t -c "SELECT pg_is_in_recovery();" 2>/dev/null \
        | grep -q f; then
      echo "$pod"; return 0
    fi
  done
  echo "ERROR: No primary DB pod for $ns/$prefix" >&2; return 1
}

psql_one() {
  local ns=$1 pod=$2 db=$3 sql=$4
  kubectl exec -n "$ns" "$pod" -c postgres -- \
    psql -U postgres -d "$db" -t -A -c "$sql" 2>/dev/null | tr -d '[:space:]'
}

psql_rows() {
  local ns=$1 pod=$2 db=$3 sql=$4
  kubectl exec -n "$ns" "$pod" -c postgres -- \
    psql -U postgres -d "$db" -t -A -F'|' -c "$sql" 2>/dev/null
}

run_psql() {
  local ns=$1 pod=$2 db=$3 sql=$4 label=$5
  if $DRY_RUN; then
    echo "    [DRY-RUN] $label"
    echo "              SQL: $sql"
  else
    kubectl exec -n "$ns" "$pod" -c postgres -- \
      psql -U postgres -d "$db" -c "$sql" > /dev/null
    echo "    OK   $label"
  fi
}

prompt_password() {
  local prompt="$1" __resultvar="$2"
  local value
  read -rs -p "$prompt" value; echo
  [[ -n "$value" ]] || die "password cannot be empty"
  printf -v "$__resultvar" '%s' "$value"
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo "======================================================================"
echo " DR Fix: Seed OPS Node + Trigger SDDC LCM Refresh (V1.0)"
$DRY_RUN && echo " *** DRY-RUN MODE — no changes will be written ***"
echo "======================================================================"
echo

# =============================================================================
# Step 1: Locate the primary SDDC LCM DB pod.
# =============================================================================
echo "Step 1: Locating primary SDDC LCM DB pod..."
SDDC_DB_POD=$(find_primary_pod "$SDDC_NS" "vcf-sddc-lcm-db") || exit 1
log "SDDC LCM DB: $SDDC_DB_POD"
echo

# =============================================================================
# Step 2: Read the OPS component's id / component_id / fqdn / version.
# =============================================================================
echo "Step 2: Reading OPS component from SDDC LCM DB..."

COUNT=$(psql_one "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" \
  "SELECT COUNT(*) FROM component WHERE component_type = 'OPS';")

if [[ "${COUNT:-0}" -eq 0 ]]; then
  die "no OPS component found in SDDC LCM DB — nothing to do."
elif [[ "$COUNT" -gt 1 ]]; then
  die "found $COUNT OPS components in SDDC LCM DB — expected exactly 1; refusing to guess, handle manually."
fi

ROW=$(psql_rows "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" \
  "SELECT id, component_id, fqdn, version FROM component WHERE component_type = 'OPS' LIMIT 1;")
IFS='|' read -r ID COMPONENT_ID FQDN VERSION <<< "$ROW"

[[ -n "$ID" && -n "$COMPONENT_ID" && -n "$FQDN" ]] || die "could not parse OPS component row: '$ROW'"

log "id (internal PK)  : $ID"
log "component_id      : $COMPONENT_ID"
log "fqdn               : $FQDN"
log "version            : ${VERSION:-unknown}"
echo

# =============================================================================
# Step 3: Seed a MASTER node row for this component, if one doesn't already
#         exist (node.component_id is a FK to component.id, the internal PK
#         - NOT component.component_id).
# =============================================================================
echo "Step 3: Seeding MASTER node row (SDDC LCM DB)..."

EXISTING_NODE=$(psql_one "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" \
  "SELECT COUNT(*) FROM node WHERE component_id = '${ID}' AND node_type = 'MASTER';")

INSERT_SQL="INSERT INTO node (id, node_type, node_id, fqdn, component_id, version)
     VALUES (gen_random_uuid(), 'MASTER', gen_random_uuid(), '${FQDN}', '${ID}', '${VERSION}');"

if $DRY_RUN; then
  # Always show the would-be INSERT in dry-run, even if a real run would
  # skip it because a MASTER row already exists - dry-run is a preview, so
  # what it *would* do (absent the idempotency check) should stay visible.
  echo "    [DRY-RUN] INSERT MASTER node row for OPS component ($COMPONENT_ID)"
  echo "              SQL: $INSERT_SQL"
  if [[ "${EXISTING_NODE:-0}" -ge 1 ]]; then
    log "NOTE a MASTER node row already exists for this component — a real run would skip the above and do nothing."
  fi
elif [[ "${EXISTING_NODE:-0}" -ge 1 ]]; then
  log "OK   a MASTER node row already exists for this component — skipping insert."
else
  run_psql "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" \
    "$INSERT_SQL" \
    "INSERT MASTER node row for OPS component ($COMPONENT_ID)"
fi
echo

# =============================================================================
# Step 4: Acquire a bearer token (admin@vsp.local) against this cluster's own
#         identity endpoint.
# =============================================================================
echo "Step 4: Acquiring admin@vsp.local token..."

INGRESS_FQDN=$(kubectl get configmap global-config -n "$PLATFORM_NS" -o jsonpath='{.data.ingress\.platform\.fqdn}' 2>/dev/null || echo "")
[[ -n "$INGRESS_FQDN" ]] || die "could not read ingress FQDN from global-config ($PLATFORM_NS); check KUBECONFIG."
log "identity endpoint  : https://${INGRESS_FQDN}"

if [[ -z "$VSP_ADMIN_PASSWORD" ]]; then
  prompt_password "admin@vsp.local password for ${INGRESS_FQDN}: " VSP_ADMIN_PASSWORD
fi

if $DRY_RUN; then
  log "[DRY-RUN] would POST https://${INGRESS_FQDN}/api/v1/identity/token (admin@vsp.local)"
  TOKEN="dry-run-token"
else
  TOKEN_RESP=$(curl -sk "https://${INGRESS_FQDN}/api/v1/identity/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode grant_type=password \
    --data-urlencode "username=admin@vsp.local" \
    --data-urlencode "password=${VSP_ADMIN_PASSWORD}")
  TOKEN=$(printf '%s' "$TOKEN_RESP" | jq -r '.access_token // empty')
  if [[ -z "$TOKEN" ]]; then
    echo "ERROR: failed to acquire token. Response:" >&2
    printf '%s\n' "$TOKEN_RESP" | sed 's/^/  /' >&2
    exit 1
  fi
  log "OK   token acquired"
fi
echo

# =============================================================================
# Step 5: Trigger SDDC LCM's action=refresh for the OPS component, from
#         inside the sddc-build-service pod (its local API port).
# =============================================================================
echo "Step 5: Triggering SDDC LCM refresh for component ${COMPONENT_ID}..."

SBS_POD=$(kubectl get pods -n "$SDDC_NS" -o name 2>/dev/null | grep -m1 'sddc-build-service' | cut -d/ -f2)
[[ -n "$SBS_POD" ]] || die "could not find a sddc-build-service pod in namespace $SDDC_NS"
log "sddc-build-service pod: $SBS_POD"

if $DRY_RUN; then
  log "[DRY-RUN] would exec into $SBS_POD and POST https://localhost:9134/sddc-lcm/v1/components/${COMPONENT_ID}?action=refresh"
else
  # Token is piped over stdin into the pod rather than passed as a curl
  # argument, so it never appears in this shell's or the pod's process list.
  POD_SCRIPT='
    read -r TOK
    HC=$(curl -sk -o /tmp/refresh_resp.$$ -w "%{http_code}" -X POST \
      "https://localhost:9134/sddc-lcm/v1/components/'"${COMPONENT_ID}"'?action=refresh" \
      -H "Authorization: Bearer ${TOK}" -H "Content-Type: application/json")
    echo "HTTP ${HC}"
    cat /tmp/refresh_resp.$$
    rm -f /tmp/refresh_resp.$$
  '
  REFRESH_OUT=$(printf '%s\n' "$TOKEN" | kubectl exec -i -n "$SDDC_NS" "$SBS_POD" -- sh -c "$POD_SCRIPT")
  echo "$REFRESH_OUT" | sed 's/^/  /'
  if ! echo "$REFRESH_OUT" | head -1 | grep -Eq "HTTP 20[0-9]"; then
    die "refresh request did not return 2xx (see response above)."
  fi
  log "OK   refresh triggered"
fi
echo

echo "======================================================================"
echo " Done."
echo " SDDC LCM will now (re)discover OPS component ${COMPONENT_ID}'s real"
echo " node topology live from ${FQDN}. Verify with:"
echo "   kubectl exec -n $SDDC_NS $SDDC_DB_POD -c postgres -- \\"
echo "     psql -U postgres -d $SDDC_DB -c \"SELECT * FROM node WHERE component_id = '${ID}';\""
echo "======================================================================"

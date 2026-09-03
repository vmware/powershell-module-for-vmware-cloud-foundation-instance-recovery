#!/usr/bin/env bash
# =============================================================================
# Re-register a component with VCF Operations after DR failover.
# =============================================================================
#
# update_vcfa_registration.sh re-points a component's Fleet LCM / SDDC LCM
# rows at the target instance, but does not touch VCF Operations: Ops still
# holds a stale component record pointing at the old instance. This script
# closes that gap:
#
#   1. Acquire an Ops auth token (admin login).
#   2. DELETE the stale component record from Ops
#      (DELETE /suite-api/internal/components/<component-id>).
#   2b. Poll GET .../components/<component-id> every 15s for up to 2 minutes,
#      waiting for a 404 - the delete above is async (202 = queued, not
#      complete), so this avoids racing the refresh below against an
#      unfinished delete. Proceeds with a warning if it never sees a 404.
#   3. Get a Fleet LCM access token (admin@vsp.local, via $KUBECONFIG to read
#      the target cluster's Fleet FQDN from global-config).
#   4. POST .../components/<component-id>?action=refresh on Fleet LCM, which
#      makes Fleet LCM re-register the component with Ops from scratch.
#
# Run with -h/--help for full usage. Set KUBECONFIG to the target DR cluster
# before running. Use --dry-run to preview all changes without applying them.
#
# Both the Ops and Fleet LCM admin passwords are prompted for upfront (before
# Step 1) if not already set via env var, so a missing password is caught
# before Step 2's destructive delete rather than mid-run afterward.
# =============================================================================

set -uo pipefail   # deliberately NOT -e: `read` returns 1 at EOF and would abort.

# ---- configurable constants (rarely need changing) --------------------------
FLEET_NS="vcf-fleet-lcm"
FLEET_DB="vcffleetlcmdb"
FLEET_DB_PODS=(vcf-fleet-lcm-db-0 vcf-fleet-lcm-db-1 vcf-fleet-lcm-db-2)

# ---- args -------------------------------------------------------------------
OPS_FQDN=""
COMPONENT_ID=""
COMPONENT_FQDN=""
OPS_USERNAME="${OPS_USERNAME:-admin}"
OPS_PASSWORD="${OPS_ADMIN_PASSWORD:-}"
FLEET_PASSWORD="${FLEET_ADMIN_PASSWORD:-}"
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage:
  export KUBECONFIG=<target-DR-cluster-kubeconfig>
  ./update_registration_in_ops.sh --ops-fqdn <ops-fqdn> --component-id <component-id> \
      [--ops-username <user>] [--dry-run]

Re-registers a component with VCF Operations after DR failover: deletes its
stale Ops component record, then triggers Fleet LCM to re-register it with
Ops from scratch. Run this AFTER update_vcfa_registration.sh (or the
equivalent registration step for the component type in question) has already
re-pointed the component's Fleet LCM / SDDC LCM rows at the target instance.

Options:
  --ops-fqdn FQDN        (required) FQDN/IP of the VCF Operations appliance,
                         e.g. vcfops1.vrack.vsphere.local.
  --component-id ID      Fleet LCM component id of the component to
                         re-register with Ops (the same id used by
                         update_vcfa_registration.sh / Fleet LCM's inventory).
                         Exactly one of --component-id / --component-fqdn is
                         required.
  --component-fqdn FQDN  Alternative to --component-id: looks up the
                         component id from Fleet LCM's own DB by fqdn
                         (SELECT DISTINCT component_id FROM component WHERE
                         fqdn=<FQDN>). Fails if zero or more than one
                         component_id matches - pass --component-id directly
                         to disambiguate.
  --ops-username USER    Ops admin username. Default: admin (or
                         $OPS_USERNAME).
  --dry-run              Show what would be done without making changes.
  -h, --help             Show this help and exit.

Passwords:
  Ops admin password         taken from $OPS_ADMIN_PASSWORD, else prompted.
  Fleet LCM admin@vsp.local  taken from $FLEET_ADMIN_PASSWORD, else prompted.
  Neither is ever echoed or logged.

Environment:
  KUBECONFIG             (required) Must point to the TARGET DR cluster.
                         Used only to read the Fleet FQDN out of the
                         global-config ConfigMap in vmsp-platform.

Examples:
  export KUBECONFIG=~/Downloads/inst2.kubeconfig
  ./update_registration_in_ops.sh --ops-fqdn vcfops1.vrack.vsphere.local \
      --component-id 3f9c1e2a-... --dry-run
  ./update_registration_in_ops.sh --ops-fqdn vcfops1.vrack.vsphere.local \
      --component-id 3f9c1e2a-...
  ./update_registration_in_ops.sh --ops-fqdn vcfops1.vrack.vsphere.local \
      --component-fqdn inst1-new-vrli.fst.com
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ops-fqdn)       OPS_FQDN="$2"; shift 2 ;;
    --component-id)   COMPONENT_ID="$2"; shift 2 ;;
    --component-fqdn) COMPONENT_FQDN="$2"; shift 2 ;;
    --ops-username)   OPS_USERNAME="$2"; shift 2 ;;
    --dry-run)        DRY_RUN=true; shift ;;
    -h|--help)        usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

[[ -n "$OPS_FQDN" ]] || { echo "ERROR: --ops-fqdn is required" >&2; usage 1; }
if [[ -n "$COMPONENT_ID" && -n "$COMPONENT_FQDN" ]]; then
  echo "ERROR: pass only one of --component-id / --component-fqdn" >&2; usage 1
fi
if [[ -z "$COMPONENT_ID" && -z "$COMPONENT_FQDN" ]]; then
  echo "ERROR: one of --component-id / --component-fqdn is required" >&2; usage 1
fi
[[ -n "${KUBECONFIG:-}" ]] || { echo "ERROR: KUBECONFIG is not set. Export it (pointing to the target DR cluster) before running." >&2; exit 1; }

command -v jq      >/dev/null 2>&1 || { echo "ERROR: jq is required (used to build/parse JSON safely). Install it and re-run." >&2; exit 1; }
command -v curl    >/dev/null 2>&1 || { echo "ERROR: curl is required." >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl is required." >&2; exit 1; }

log()  { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

# Looks up component_id by fqdn in Fleet LCM's own DB. Any pod (primary or
# replica) works since this is a read - Postgres streaming replicas serve
# SELECTs fine, unlike the writes elsewhere in this script suite that need
# the primary. Fails loudly on zero or multiple matches rather than guessing.
resolve_component_id_by_fqdn() {
  local fqdn=$1 pod ids=""
  for pod in "${FLEET_DB_PODS[@]}"; do
    ids=$(kubectl exec "$pod" -n "$FLEET_NS" -c postgres -- \
      psql -U postgres -d "$FLEET_DB" -t -A -c \
      "SELECT DISTINCT component_id FROM component WHERE fqdn='${fqdn}';" 2>/dev/null) && [[ -n "$ids" ]] && break
  done
  local count
  count=$(printf '%s\n' "$ids" | sed '/^$/d' | wc -l | tr -d '[:space:]')
  if [[ "${count:-0}" -eq 0 ]]; then
    echo "ERROR: no component found in Fleet LCM DB with fqdn='${fqdn}'" >&2
    exit 1
  elif [[ "$count" -gt 1 ]]; then
    echo "ERROR: found $count distinct component_ids with fqdn='${fqdn}' - pass --component-id directly to disambiguate:" >&2
    printf '%s\n' "$ids" | sed 's/^/  /' >&2
    exit 1
  fi
  printf '%s' "$ids" | tr -d '[:space:]'
}

if [[ -n "$COMPONENT_FQDN" ]]; then
  COMPONENT_ID=$(resolve_component_id_by_fqdn "$COMPONENT_FQDN")
fi

# Reads a password into $2 with prompt $1, bypassing this script's own
# stdout/stdin — needed because callers (e.g. update_vcfa_registration.sh)
# invoke this script as the left side of a pipe (`... | sed ...`) to indent
# its output, and a plain `read -p` in that position does not reliably block
# for terminal input: the prompt still gets printed (into the pipe), but the
# read can return immediately empty instead of waiting on you to type.
prompt_password() {
  local prompt=$1 __outvar=$2
  if [[ ! -r /dev/tty ]]; then
    echo "ERROR: no terminal available to prompt for a password (set the corresponding env var instead)" >&2
    exit 1
  fi
  printf '%s' "$prompt" > /dev/tty
  read -rs "$__outvar" < /dev/tty
  echo > /dev/tty
}

echo "======================================================================"
echo " Re-register component with VCF Operations after DR failover"
echo " Ops FQDN       : $OPS_FQDN"
if [[ -n "$COMPONENT_FQDN" ]]; then
  echo " Component FQDN : $COMPONENT_FQDN (resolved -> $COMPONENT_ID)"
else
  echo " Component ID   : $COMPONENT_ID"
fi
echo " KUBECONFIG     : $KUBECONFIG"
$DRY_RUN && echo " *** DRY-RUN: no changes will be written ***"
echo "======================================================================"

if [[ -z "$OPS_PASSWORD" ]]; then
  prompt_password "${OPS_USERNAME} password for ${OPS_FQDN}: " OPS_PASSWORD
fi
[[ -n "$OPS_PASSWORD" ]] || { echo "ERROR: Ops password is empty" >&2; exit 1; }

# Fleet LCM FQDN is only needed for its own auth token (Steps 3-4), but it's
# resolved here rather than there so its password can be prompted for upfront
# alongside the Ops password — otherwise a missing $FLEET_ADMIN_PASSWORD would
# only surface after Step 2 has already deleted the stale Ops component record.
FLEET_FQDN=$(kubectl get configmap global-config -n vmsp-platform -o jsonpath='{.data.ingress\.fleet\.fqdn}' 2>/dev/null || echo "")
[[ -n "$FLEET_FQDN" ]] || { echo "ERROR: could not read Fleet FQDN from global-config (vmsp-platform); check KUBECONFIG." >&2; exit 1; }

if [[ -z "$FLEET_PASSWORD" ]]; then
  prompt_password "admin@vsp.local for the DR target VCF Services Runtime: " FLEET_PASSWORD
fi
[[ -n "$FLEET_PASSWORD" ]] || { echo "ERROR: Fleet LCM password is empty" >&2; exit 1; }

# =============================================================================
# Step 1: Acquire an Ops auth token.
# =============================================================================
step "Step 1: Acquire VCF Operations auth token"

# Build the JSON body with jq -n, NOT string interpolation: the password is
# passed as a --arg, so jq handles all JSON-escaping (quotes, backslashes,
# unicode, control chars) regardless of what's in it. String-interpolating
# the password directly into a JSON literal (e.g. "{\"password\":\"$PW\"}")
# breaks/corrupts the request body if the password contains a `"` or `\`.
OPS_TOKEN_BODY=$(jq -n --arg u "$OPS_USERNAME" --arg p "$OPS_PASSWORD" '{username:$u,password:$p}')

OPS_TOKEN_RESP=$(curl -sk -X POST "https://${OPS_FQDN}/suite-api/api/auth/token/acquire" \
  -H "Content-Type: application/json" -H "Accept: application/json" \
  -d "$OPS_TOKEN_BODY")

OPS_TOKEN=$(printf '%s' "$OPS_TOKEN_RESP" | jq -r '.token // empty')
if [[ -z "$OPS_TOKEN" ]]; then
  echo "ERROR: failed to acquire Ops token. Response:" >&2
  printf '%s\n' "$OPS_TOKEN_RESP" | sed 's/^/  /' >&2
  exit 1
fi
log "OK   Ops token acquired"

# =============================================================================
# Step 2: Delete the stale component record from Ops.
# =============================================================================
step "Step 2: Delete stale component record from VCF Operations"

if $DRY_RUN; then
  log "[DRY-RUN] would DELETE https://${OPS_FQDN}/suite-api/internal/components/${COMPONENT_ID}"
else
  OPS_DELETE_HTTP_CODE=$(curl -sk -o /tmp/ops_delete_resp.$$ -w '%{http_code}' \
    -H "Authorization: vRealizeOpsToken ${OPS_TOKEN}" \
    -H "X-vRealizeOps-API-use-unsupported: true" \
    -X DELETE "https://${OPS_FQDN}/suite-api/internal/components/${COMPONENT_ID}")
  OPS_DELETE_BODY=$(cat /tmp/ops_delete_resp.$$ 2>/dev/null)
  rm -f /tmp/ops_delete_resp.$$
  # 202 = accepted for async processing (Ops queues the delete and returns a
  # requestId immediately, without waiting for it to complete).
  # 404 is treated as success: the record is already gone (idempotent).
  # Ops also reports "already absent" as HTTP 400 with a body like
  # {"message":"Not found :: Component with uuid <id>."} rather than a
  # proper 404 - treat that the same way.
  if [[ "$OPS_DELETE_HTTP_CODE" == "200" || "$OPS_DELETE_HTTP_CODE" == "202" || "$OPS_DELETE_HTTP_CODE" == "204" ]]; then
    log "OK   deleted component ${COMPONENT_ID} from Ops (HTTP ${OPS_DELETE_HTTP_CODE})"
  elif [[ "$OPS_DELETE_HTTP_CODE" == "404" ]]; then
    log "OK   component ${COMPONENT_ID} already absent from Ops (HTTP 404) — nothing to do"
  elif [[ "$OPS_DELETE_HTTP_CODE" == "400" && "$OPS_DELETE_BODY" == *"Not found"* ]]; then
    log "OK   component ${COMPONENT_ID} already absent from Ops (HTTP 400/Not found) — nothing to do"
  else
    echo "ERROR: delete failed, HTTP ${OPS_DELETE_HTTP_CODE}:" >&2
    printf '%s\n' "$OPS_DELETE_BODY" | sed 's/^/  /' >&2
    exit 1
  fi
fi

# =============================================================================
# Step 2b: Wait for the delete to actually finish before triggering the Fleet
#          LCM refresh. The delete above is async (HTTP 202: queued, not
#          complete) - if the refresh runs while Ops still has the old
#          component record, Ops can end up re-registering on top of
#          not-yet-torn-down state instead of a clean create. Poll every 15s
#          for up to 2 minutes; a 404 means the record is actually gone.
# =============================================================================
step "Step 2b: Wait for component to be deleted from Ops"

if $DRY_RUN; then
  log "[DRY-RUN] would poll GET https://${OPS_FQDN}/suite-api/internal/components/${COMPONENT_ID} (every 15s, up to 2m)"
else
  POLL_INTERVAL=15
  POLL_TIMEOUT=120
  POLL_ELAPSED=0
  DELETE_CONFIRMED=false
  while [[ $POLL_ELAPSED -lt $POLL_TIMEOUT ]]; do
    POLL_HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
      -H "Authorization: vRealizeOpsToken ${OPS_TOKEN}" \
      -H "X-vRealizeOps-API-use-unsupported: true" \
      "https://${OPS_FQDN}/suite-api/internal/components/${COMPONENT_ID}")
    if [[ "$POLL_HTTP_CODE" == "404" ]]; then
      log "OK   component ${COMPONENT_ID} confirmed deleted from Ops (HTTP 404, after ${POLL_ELAPSED}s)"
      DELETE_CONFIRMED=true
      break
    fi
    log "still present (HTTP ${POLL_HTTP_CODE}) — waiting ${POLL_INTERVAL}s (${POLL_ELAPSED}/${POLL_TIMEOUT}s elapsed)"
    sleep "$POLL_INTERVAL"
    POLL_ELAPSED=$((POLL_ELAPSED + POLL_INTERVAL))
  done
  if ! $DELETE_CONFIRMED; then
    log "WARN component still present in Ops after ${POLL_TIMEOUT}s — proceeding anyway, but the"
    log "     Fleet LCM refresh below may race with an unfinished delete. Check the Ops UI"
    log "     (Control Panel > Management Tasks) for a stuck delete before re-running this script."
  fi
fi

# =============================================================================
# Step 3: Get a Fleet LCM access token for the target DR cluster.
# =============================================================================
step "Step 3: Acquire Fleet LCM access token (target cluster)"

log "Fleet LCM FQDN : $FLEET_FQDN"

FLEET_TOKEN_RESP=$(curl -sk "https://${FLEET_FQDN}/api/v1/identity/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode grant_type=password \
  --data-urlencode "username=admin@vsp.local" \
  --data-urlencode "password=${FLEET_PASSWORD}")
LCM_TOKEN=$(printf '%s' "$FLEET_TOKEN_RESP" | jq -r '.access_token // empty')
if [[ -z "$LCM_TOKEN" ]]; then
  echo "ERROR: failed to acquire Fleet LCM token. Response:" >&2
  printf '%s\n' "$FLEET_TOKEN_RESP" | sed 's/^/  /' >&2
  exit 1
fi
log "OK   Fleet LCM token acquired"

# =============================================================================
# Step 4: Trigger Fleet LCM to refresh/re-register the component with Ops.
# =============================================================================
step "Step 4: Trigger Fleet LCM refresh for component ${COMPONENT_ID}"

if $DRY_RUN; then
  log "[DRY-RUN] would POST https://${FLEET_FQDN}/fleet-lcm/v1/components/${COMPONENT_ID}?action=refresh"
else
  FLEET_REFRESH_HTTP_CODE=$(curl -sk -o /tmp/fleet_refresh_resp.$$ -w '%{http_code}' \
    --request POST \
    --url "https://${FLEET_FQDN}/fleet-lcm/v1/components/${COMPONENT_ID}?action=refresh" \
    --header "Authorization: Bearer ${LCM_TOKEN}" \
    --header "Content-Type: application/json")
  FLEET_REFRESH_BODY=$(cat /tmp/fleet_refresh_resp.$$ 2>/dev/null)
  rm -f /tmp/fleet_refresh_resp.$$
  if [[ "$FLEET_REFRESH_HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then
    log "OK   refresh triggered (HTTP ${FLEET_REFRESH_HTTP_CODE})"
  else
    echo "ERROR: refresh failed, HTTP ${FLEET_REFRESH_HTTP_CODE}:" >&2
    printf '%s\n' "$FLEET_REFRESH_BODY" | sed 's/^/  /' >&2
    exit 1
  fi
fi

echo
echo "======================================================================"
$DRY_RUN && echo " DRY-RUN complete — no changes written." || echo " Re-registration with VCF Operations triggered."
echo " Ops re-discovers/re-adds the component asynchronously; check the"
echo " Ops UI (or GET /suite-api/internal/components/${COMPONENT_ID}) after"
echo " a few minutes to confirm it reappears with current data."
echo "======================================================================"

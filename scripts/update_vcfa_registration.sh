#!/usr/bin/env bash
# =============================================================================
# Register VCFA and its consumption VSP cluster on the target VCF instance.
# =============================================================================
#
# Registers the VCFA component and its consumption VSP cluster ("VCF services
# runtime") with the target instance's SDDC LCM and Fleet LCM. Idempotent.
#
# Steps:
#   1. Create a VSP "admin" service account on the consumption cluster
#      (POST /api/v1/identity/service-accounts).
#   2. Store its clientId/clientSecret as a labeled secret in the target SDDC LCM
#      namespace (vcf.broadcom.com/component-type=vsp, component-id=<clusterId>).
#   3. Add the consumption VSP cluster to the target SDDC LCM inventory.
#   4. Point or create the Fleet LCM row for that VSP cluster at the target SDDC LCM,
#      safely purging any obsolete rows sharing the same FQDN.
#   5. Register the VCFA component in the target SDDC LCM inventory and point its
#      Fleet LCM row at the target SDDC LCM.
#   5b. Same as step 5, but for the vcd-migrator component if the consumption
#      cluster has one (this is "Step 4b" in the script's own progress output,
#      right after step 5's "Step 4"). id/fqdn/version/size always come from
#      Step 1's live query of the cluster, never from Fleet LCM DB, since any
#      pre-existing Fleet LCM row for it could be stale. Skipped if the
#      cluster has no vcd-migrator component.
#   6. Create the VCFA service accounts (admin + adminextra) that VCFA needs to
#      register itself with VCF Operations - via create_vcfa_service_account.sh,
#      which must sit next to this script. Without them, VCFA-Ops registration
#      always fails with NoSuchElementException, so this step always runs
#      (skipped only if step 5 found no VCFA component to register).
#   7. Re-register VCFA with VCF Operations itself - via
#      update_registration_in_ops.sh, which must also sit next to this script
#      (this is "Step 6" in the script's own progress output, immediately
#      after the previous item's "Step 5"). Deletes VCFA's stale Ops
#      component record and triggers Fleet LCM to re-register it from
#      scratch. --ops-fqdn is required; this step is skipped only if step 4
#      found no VCFA component to register.
#
# Cluster-facing calls (token, create SA, create secret) run inside the target
# cluster's sddc-build-service pod, so the clientSecret never leaves the cluster
# and is never printed.
#
# create_vcfa_service_account.sh and update_registration_in_ops.sh are helper
# scripts for the last two items above - they are not meant to be run
# standalone except for targeted troubleshooting (see README.md).
#
# Run with -h/--help for full usage. Set KUBECONFIG to the target DR cluster
# before running. Use --dry-run to preview all changes without applying them.
# =============================================================================

set -uo pipefail   # deliberately NOT -e: `read` returns 1 at EOF and would abort.

# ---- configurable constants (rarely need changing) --------------------------
SDDC_NS="vcf-sddc-lcm"
FLEET_NS="vcf-fleet-lcm"
SDDC_DB="vcfsddclcmdb"
FLEET_DB="vcffleetlcmdb"
SDDC_DB_PREFIX="vcf-sddc-lcm-db"
FLEET_DB_PREFIX="vcf-fleet-lcm-db"
CLIENT_NAME="admin"                     # matches the real product convention (iam-lib
                                         # generateSecretName: "vcf-iam-" + type + "-" + clientName,
                                         # e.g. vcf-iam-vsp-admin - no componentId suffix)

# Generates a UUIDv7 in pure SQL (component.id must be UUIDv7).
UUIDV7_SQL="(WITH src AS (
  SELECT overlay(uuid_send(gen_random_uuid())
         placing substring(int8send(floor(extract(epoch from clock_timestamp())*1000)::bigint) from 3)
         from 1 for 6) AS b)
 SELECT encode(set_byte(set_byte(b,6,(get_byte(b,6)&15)|112),8,(get_byte(b,8)&63)|128),'hex')::uuid FROM src)"

# ---- args -------------------------------------------------------------------
VCFA_RUNTIME_FQDN=""
PASSWORD="${VCFA_ADMIN_PASSWORD:-}"
VCFA_SYSTEM_PASSWORD="${VCFA_SYSTEM_PASSWORD:-}"   # admin@System on the VCFA app itself -
                                                    # distinct from $PASSWORD (admin@vsp.local
                                                    # on the consumption cluster) - do not conflate.
OPS_FQDN=""
OPS_PASSWORD="${OPS_ADMIN_PASSWORD:-}"             # VCF Operations admin password - a third,
                                                    # distinct credential from the two above.
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage:
  export KUBECONFIG=<target-DR-cluster-kubeconfig>
  ./update_vcfa_registration.sh --vcfa-runtime-fqdn <FQDN> --ops-fqdn <ops-fqdn> \
      [--password <pw>] [--vcfa-system-password <pw>] [--ops-password <pw>] \
      [--dry-run]

Registers the VCFA component and its consumption VSP cluster ("VCF services
runtime") with the target DR instance's SDDC LCM and Fleet LCM, creates the
VCFA service accounts VCFA needs to register itself with VCF Operations, and
re-registers VCFA with VCF Operations itself. Idempotent.

Options:
  --vcfa-runtime-fqdn FQDN   (required) FQDN of the VCFA consumption cluster
                             ("VCF services runtime"), e.g.
                             inst1-vcfa-runtime.fst.com. This is the VSP platform
                             the script logs into and registers.
  --ops-fqdn FQDN            (required) FQDN/IP of the VCF Operations appliance.
                             Used for step 6: delete VCFA's stale Ops component
                             record and trigger Fleet LCM to re-register it.
  --password PW              admin@vsp.local password for that consumption cluster.
                             If omitted, taken from $VCFA_ADMIN_PASSWORD, else
                             prompted. Never echoed; passed to the pod via stdin.
  --vcfa-system-password PW  admin@System password for the VCFA app itself (a
                             different account on a different system than
                             --password). Used only for step 5, creating
                             the VCFA service accounts needed for VCFA-Ops
                             registration. If omitted, taken from
                             $VCFA_SYSTEM_PASSWORD, else prompted.
  --ops-password PW          VCF Operations admin password (a third, distinct
                             credential from --password/--vcfa-system-password).
                             If omitted, taken from $OPS_ADMIN_PASSWORD, else
                             prompted.
  --dry-run                  Show what would be done without making changes.
  -h, --help                 Show this help and exit.

Environment:
  KUBECONFIG                (required) Must be set before running and must point
                            to the TARGET DR cluster (the instance VCFA was
                            failed over to). Used for all kubectl access — the
                            SDDC/Fleet LCM databases, the sddc-build-service pod,
                            and (for step 6) reading the target Fleet FQDN.

Requires create_vcfa_service_account.sh and update_registration_in_ops.sh in
the same directory as this script - both are helpers for this script and are
not meant to be run standalone (see README.md).

Examples:
  export KUBECONFIG=~/Downloads/inst2.kubeconfig
  ./update_vcfa_registration.sh --vcfa-runtime-fqdn inst1-vcfa-runtime.fst.com \
      --ops-fqdn inst4-vcfops.fst.com --dry-run
  ./update_vcfa_registration.sh --vcfa-runtime-fqdn inst1-vcfa-runtime.fst.com \
      --ops-fqdn inst4-vcfops.fst.com
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vcfa-runtime-fqdn)  VCFA_RUNTIME_FQDN="$2"; shift 2 ;;
    --password)           PASSWORD="$2"; shift 2 ;;
    --vcfa-system-password) VCFA_SYSTEM_PASSWORD="$2"; shift 2 ;;
    --ops-fqdn)            OPS_FQDN="$2"; shift 2 ;;
    --ops-password)        OPS_PASSWORD="$2"; shift 2 ;;
    --dry-run)            DRY_RUN=true; shift ;;
    -h|--help)           usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

[[ -n "$VCFA_RUNTIME_FQDN" ]] || { echo "ERROR: --vcfa-runtime-fqdn is required" >&2; usage 1; }
[[ -n "$OPS_FQDN" ]]         || { echo "ERROR: --ops-fqdn is required" >&2; usage 1; }
[[ -n "${KUBECONFIG:-}" ]] || { echo "ERROR: KUBECONFIG is not set. Export it (pointing to the target DR cluster) before running." >&2; exit 1; }

KC=(kubectl)

# Sanity: KUBECONFIG must point at the target DR management-services cluster.
"${KC[@]}" get ns "$SDDC_NS" >/dev/null 2>&1 || {
  echo "ERROR: namespace '$SDDC_NS' not reachable via \$KUBECONFIG ($KUBECONFIG)." >&2
  echo "       Ensure KUBECONFIG points to the TARGET DR cluster." >&2
  exit 1
}

if [[ -z "$PASSWORD" ]]; then
  read -rs -p "admin@vsp.local password for ${VCFA_RUNTIME_FQDN}: " PASSWORD; echo
fi
[[ -n "$PASSWORD" ]] || { echo "ERROR: password is empty" >&2; exit 1; }

log()  { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

echo "======================================================================"
echo " Register VCFA + consumption VSP cluster on the target DR instance"
echo " VCFA runtime FQDN : $VCFA_RUNTIME_FQDN"
echo " KUBECONFIG        : $KUBECONFIG"
$DRY_RUN && echo " *** DRY-RUN: no changes will be written ***"
echo "======================================================================"

# ---- locate pods ------------------------------------------------------------
step "Step 0: Locating pods on target cluster"
SBS_POD=$("${KC[@]}" get pods -n "$SDDC_NS" -o name 2>/dev/null | grep -m1 'sddc-build-service' | cut -d/ -f2)
[[ -n "$SBS_POD" ]] || { echo "ERROR: could not find sddc-build-service pod in $SDDC_NS" >&2; exit 1; }
log "sddc-build-service pod: $SBS_POD"

find_primary() {   # ns prefix  -> echoes primary pod name (pg_is_in_recovery = f)
  local ns=$1 prefix=$2 pod rec
  for i in 0 1 2; do
    pod="${prefix}-${i}"
    rec=$("${KC[@]}" exec "$pod" -n "$ns" -c postgres -- \
          psql -U postgres -t -A -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d '[:space:]')
    [[ "$rec" == "f" ]] && { echo "$pod"; return 0; }
  done
  return 1
}

SDDC_DB_POD=$(find_primary "$SDDC_NS" "$SDDC_DB_PREFIX") || { echo "ERROR: no SDDC LCM DB primary found" >&2; exit 1; }
FLEET_DB_POD=$(find_primary "$FLEET_NS" "$FLEET_DB_PREFIX") || { echo "ERROR: no Fleet LCM DB primary found" >&2; exit 1; }
log "SDDC LCM DB primary : $SDDC_DB_POD"
log "Fleet LCM DB primary: $FLEET_DB_POD"

# scalar read against a specific db (tuple-only)
q_sddc()  { "${KC[@]}" exec "$SDDC_DB_POD"  -n "$SDDC_NS"  -c postgres -- psql -U postgres -d "$SDDC_DB"  -t -A -c "$1" 2>/dev/null | tr -d '[:space:]'; }
q_fleet() { "${KC[@]}" exec "$FLEET_DB_POD" -n "$FLEET_NS" -c postgres -- psql -U postgres -d "$FLEET_DB" -t -A -c "$1" 2>/dev/null | tr -d '[:space:]'; }
q_fleet_row() { "${KC[@]}" exec "$FLEET_DB_POD" -n "$FLEET_NS" -c postgres -- psql -U postgres -d "$FLEET_DB" -t -A -F'|' -c "$1" 2>/dev/null; }

# dry-run-aware write:  run_write <ns> <pod> <db> <label> <sql>
run_write() {
  local ns=$1 pod=$2 db=$3 label=$4 sql=$5
  if $DRY_RUN; then
    log "[DRY-RUN] $label"
    printf '%s\n' "$sql" | sed 's/^/          /'
  else
    "${KC[@]}" exec "$pod" -n "$ns" -c postgres -- psql -U postgres -d "$db" -c "$sql" 2>&1 | sed 's/^/  /'
    log "$label"
  fi
}

# Target SDDC LCM instance id = the local VCF_SDDC_LCM component id in its own DB.
TARGET_SDDC_LCM_ID=$(q_sddc "SELECT component_id FROM component WHERE component_type='VCF_SDDC_LCM' LIMIT 1;")
[[ -n "$TARGET_SDDC_LCM_ID" ]] || { echo "ERROR: could not determine target SDDC LCM id (VCF_SDDC_LCM component)" >&2; exit 1; }
log "target SDDC LCM id  : $TARGET_SDDC_LCM_ID"

# =============================================================================
# Step 1: In the sddc-build-service pod, get a token from the consumption
#         cluster, read its VSP component id/version, create the VSP admin
#         service account, and store its secret in vcf-sddc-lcm.
# =============================================================================
step "Step 1: Service account + secret (runs inside $SBS_POD; reaches $VCFA_RUNTIME_FQDN)"

POD_SCRIPT_RESOLVE='
  read -r PW; read -r FQDN
  BASE="https://$FQDN/api/v1"
  TR=$(curl -sk "$BASE/identity/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode grant_type=password \
        --data-urlencode "username=admin@vsp.local" \
        --data-urlencode "password=$PW")
  TOKEN=$(printf "%s" "$TR" | sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p")
  [ -n "$TOKEN" ] || { echo "ERR token: $(printf "%s" "$TR" | head -c 140)"; exit 3; }
  CJ=$(curl -sk "$BASE/components?type=vsp" -H "Authorization: Bearer $TOKEN")
  # Select the VSP component whose fqdn matches the target runtime FQDN. This picks
  # the correct consumption cluster and rejects a wrong/management cluster (whose
  # fqdn will not match).
  OBJ=$(printf "%s" "$CJ" | sed "s/},{/}\n{/g" | grep -F "\"fqdn\":\"$FQDN\"" | head -1)
  [ -n "$OBJ" ] || { echo "ERR no vsp component with fqdn=$FQDN: $(printf "%s" "$CJ" | head -c 160)"; exit 3; }
  COMP=$(printf "%s" "$OBJ" | sed -n "s/.*\"id\":\"\([^\"]*\)\".*/\1/p" | head -1)
  [ -n "$COMP" ] || { echo "ERR could not extract id for fqdn=$FQDN"; exit 3; }
  VER=$(printf "%s" "$OBJ" | grep -oE "\"version\":\"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[^\"]*\"" | head -1 | sed "s/.*:\"//;s/\"//")
  echo "COMPONENT_ID=$COMP"
  echo "VERSION=${VER:-unknown}"
  # vcd-migrator (if present on this cluster) - looked up live here rather than
  # from Fleet LCM DB, since any pre-existing Fleet LCM row for it could be
  # stale. Not every consumption cluster has this component, so an empty
  # result here is not an error.
  CJ2=$(curl -sk "$BASE/components?type=vcd-migrator" -H "Authorization: Bearer $TOKEN")
  OBJ2=$(printf "%s" "$CJ2" | sed "s/},{/}\n{/g" | grep -F "\"id\":\"" | head -1)
  if [ -n "$OBJ2" ]; then
    VCDM=$(printf "%s" "$OBJ2" | sed -n "s/.*\"id\":\"\([^\"]*\)\".*/\1/p" | head -1)
    VCDM_VER=$(printf "%s" "$OBJ2" | grep -oE "\"version\":\"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[^\"]*\"" | head -1 | sed "s/.*:\"//;s/\"//")
    VCDM_FQDN=$(printf "%s" "$OBJ2" | sed -n "s/.*\"fqdn\":\"\([^\"]*\)\".*/\1/p" | head -1)
    VCDM_SIZE=$(printf "%s" "$OBJ2" | sed -n "s/.*\"size\":\"\([^\"]*\)\".*/\1/p" | head -1)
  fi
  echo "VCD_MIGRATOR_ID=${VCDM:-}"
  echo "VCD_MIGRATOR_VERSION=${VCDM_VER:-unknown}"
  echo "VCD_MIGRATOR_FQDN=${VCDM_FQDN:-}"
  echo "VCD_MIGRATOR_SIZE=${VCDM_SIZE:-small}"
'

POD_OUT=$(printf '%s\n%s\n' "$PASSWORD" "$VCFA_RUNTIME_FQDN" \
          | "${KC[@]}" exec -n "$SDDC_NS" -i "$SBS_POD" -- sh -c "$POD_SCRIPT_RESOLVE" 2>&1)
POD_RC=$?
printf '%s\n' "$POD_OUT" | grep -v '^COMPONENT_ID=\|^VERSION=\|^VCD_MIGRATOR_' | sed 's/^/  /'
if [[ $POD_RC -ne 0 ]]; then echo "ERROR: step 1 failed (see above)"; exit 1; fi

COMPONENT_ID=$(printf '%s\n' "$POD_OUT" | sed -n 's/^COMPONENT_ID=//p' | head -1)
VERSION=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VERSION=//p' | head -1)
[[ -n "$COMPONENT_ID" ]] || { echo "ERROR: did not obtain consumption VSP component id"; exit 1; }
log "consumption VSP component id: $COMPONENT_ID"
log "consumption VSP version     : ${VERSION:-unknown}"

VCD_MIGRATOR_ID=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VCD_MIGRATOR_ID=//p' | head -1)
VCD_MIGRATOR_VERSION=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VCD_MIGRATOR_VERSION=//p' | head -1)
VCD_MIGRATOR_FQDN=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VCD_MIGRATOR_FQDN=//p' | head -1)
VCD_MIGRATOR_SIZE=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VCD_MIGRATOR_SIZE=//p' | head -1)
if [[ -n "$VCD_MIGRATOR_ID" ]]; then
  log "vcd-migrator component id   : $VCD_MIGRATOR_ID"
  log "vcd-migrator version        : ${VCD_MIGRATOR_VERSION:-unknown}"
fi

# 1b. Check for an existing secret via the operator's own kubectl access. (Not an
#     in-pod curl against the k8s API - that was observed to silently return no
#     matches even when a labeled secret already existed, which would have made
#     this step falsely non-idempotent.)
EXISTING_SECRET=$("${KC[@]}" get secrets -n "$SDDC_NS" \
  -l "vcf.broadcom.com/component-type=vsp,vcf.broadcom.com/component-id=${COMPONENT_ID}" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [[ -n "$EXISTING_SECRET" ]]; then
  log "OK   service-account secret already exists ($EXISTING_SECRET) — skipping creation"
elif $DRY_RUN; then
  log "[DRY-RUN] would create VSP admin service account + secret vcf-iam-vsp-${CLIENT_NAME}"
else
  # 1c. Create the service account on the consumption cluster and persist its
  #     secret in $SDDC_NS. Runs inside the pod so clientSecret never leaves
  #     the cluster and is never printed.
  POD_SCRIPT_CREATE='
    read -r PW; read -r FQDN; read -r NS; read -r CN; read -r COMP
    BASE="https://$FQDN/api/v1"
    TR=$(curl -sk "$BASE/identity/token" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          --data-urlencode grant_type=password \
          --data-urlencode "username=admin@vsp.local" \
          --data-urlencode "password=$PW")
    TOKEN=$(printf "%s" "$TR" | sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p")
    [ -n "$TOKEN" ] || { echo "ERR token: $(printf "%s" "$TR" | head -c 140)"; exit 3; }
    BODY="{\"clientName\":\"$CN\",\"componentType\":\"vsp\",\"componentId\":\"$COMP\",\"accessTokenTtl\":14440,\"roles\":[{\"name\":\"admin\",\"type\":\"vsp\"}]}"
    HC=$(printf "%s" "$BODY" | curl -sk -o /tmp/sar.$$ -w "%{http_code}" -X POST "$BASE/identity/service-accounts" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @-)
    if [ "$HC" != "201" ]; then echo "ERR create-SA HTTP $HC: $(head -c 160 /tmp/sar.$$)"; rm -f /tmp/sar.$$; exit 3; fi
    NCID=$(sed -n "s/.*\"clientId\":\"\([^\"]*\)\".*/\1/p" /tmp/sar.$$)
    NCS=$(sed -n "s/.*\"clientSecret\":\"\([^\"]*\)\".*/\1/p" /tmp/sar.$$)
    rm -f /tmp/sar.$$
    [ -n "$NCS" ] || { echo "ERR no clientSecret returned"; exit 3; }
    B64ID=$(printf "%s" "$NCID" | base64 | tr -d "\n")
    B64CS=$(printf "%s" "$NCS" | base64 | tr -d "\n")
    SNAME="vcf-iam-vsp-$CN"
    KTOK=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    CACRT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    KAPI=https://kubernetes.default.svc
    SEC="{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"type\":\"Opaque\",\"metadata\":{\"name\":\"$SNAME\",\"labels\":{\"app.kubernetes.io/managed-by\":\"vcf-identity-library\",\"vcf.broadcom.com/component-type\":\"vsp\",\"vcf.broadcom.com/component-id\":\"$COMP\",\"vcf.broadcom.com/client-name\":\"$CN\"}},\"data\":{\"clientId\":\"$B64ID\",\"clientSecret\":\"$B64CS\"}}"
    KHC=$(printf "%s" "$SEC" | curl -sk -o /tmp/kr.$$ -w "%{http_code}" -X POST "$KAPI/api/v1/namespaces/$NS/secrets" --cacert "$CACRT" -H "Authorization: Bearer $KTOK" -H "Content-Type: application/json" -d @-)
    if [ "$KHC" != "201" ]; then echo "ERR create-secret HTTP $KHC: $(head -c 160 /tmp/kr.$$)"; rm -f /tmp/kr.$$; exit 3; fi
    rm -f /tmp/kr.$$
    echo "SA_SECRET=created:$SNAME"
  '
  CREATE_OUT=$(printf '%s\n%s\n%s\n%s\n%s\n' "$PASSWORD" "$VCFA_RUNTIME_FQDN" "$SDDC_NS" "$CLIENT_NAME" "$COMPONENT_ID" \
              | "${KC[@]}" exec -n "$SDDC_NS" -i "$SBS_POD" -- sh -c "$POD_SCRIPT_CREATE" 2>&1)
  CREATE_RC=$?
  printf '%s\n' "$CREATE_OUT" | sed 's/^/  /'
  [[ $CREATE_RC -eq 0 ]] || { echo "ERROR: step 1 service-account creation failed (see above)"; exit 1; }
fi

# =============================================================================
# Step 2: SDDC LCM inventory row (VSP, non-management) so discovery can find it.
# =============================================================================
step "Step 2: SDDC LCM inventory row (target $SDDC_DB_POD)"
EXISTS_INV=$("${KC[@]}" exec "$SDDC_DB_POD" -n "$SDDC_NS" -c postgres -- psql -U postgres -d "$SDDC_DB" -t -A \
             -c "SELECT count(*) FROM component WHERE component_id='${COMPONENT_ID}';" 2>/dev/null | tr -d '[:space:]')
INV_SQL="INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version)
SELECT ${UUIDV7_SQL}, '${COMPONENT_ID}', 'VSP', 'VSP', '${VCFA_RUNTIME_FQDN}', 'medium', '${VERSION:-unknown}'
WHERE NOT EXISTS (SELECT 1 FROM component WHERE component_id='${COMPONENT_ID}');"
if [[ "${EXISTS_INV:-0}" -ge 1 ]]; then
  log "OK   inventory row already present — skipping"
elif $DRY_RUN; then
  log "[DRY-RUN] would INSERT VSP inventory row for ${VCFA_RUNTIME_FQDN}:"
  printf '%s\n' "$INV_SQL" | sed 's/^/      /'
else
  "${KC[@]}" exec "$SDDC_DB_POD" -n "$SDDC_NS" -c postgres -- psql -U postgres -d "$SDDC_DB" -c "$INV_SQL" | sed 's/^/  /'
  log "inserted VSP inventory row (${VCFA_RUNTIME_FQDN})"
fi

# =============================================================================
# Step 3: Fleet LCM VSP cluster re-home (INSERT if missing, UPDATE if present).
# =============================================================================
step "Step 3: Fleet LCM VSP cluster re-home (target $FLEET_DB_POD)"

# 3a. Delete any stale VSP entries in Fleet LCM sharing the same FQDN but a different component_id
#     (Deleting in reverse dependency order: node -> component_config -> component)
run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE stale VSP node rows for ${VCFA_RUNTIME_FQDN}" \
  "DELETE FROM node WHERE component_id IN (
     SELECT id FROM component WHERE fqdn='${VCFA_RUNTIME_FQDN}' AND component_type='VSP' AND component_id<>'${COMPONENT_ID}');"

run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE stale VSP config rows for ${VCFA_RUNTIME_FQDN}" \
  "DELETE FROM component_config WHERE component_id IN (
     SELECT id FROM component WHERE fqdn='${VCFA_RUNTIME_FQDN}' AND component_type='VSP' AND component_id<>'${COMPONENT_ID}');"

run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE stale VSP cluster rows for ${VCFA_RUNTIME_FQDN}" \
  "DELETE FROM component WHERE fqdn='${VCFA_RUNTIME_FQDN}' AND component_type='VSP' AND component_id<>'${COMPONENT_ID}';"

# 3b. Insert missing VSP cluster row or update existing row to point to target SDDC LCM
FLEET_ROWS=$("${KC[@]}" exec "$FLEET_DB_POD" -n "$FLEET_NS" -c postgres -- psql -U postgres -d "$FLEET_DB" -t -A \
             -c "SELECT count(*) FROM component WHERE component_id='${COMPONENT_ID}';" 2>/dev/null | tr -d '[:space:]')

if [[ "${FLEET_ROWS:-0}" -eq 0 ]]; then
  VSP_SQL="INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, status, version, sddc_lcm_id)
           VALUES (${UUIDV7_SQL}, '${COMPONENT_ID}', 'VSP', 'VSP', '${VCFA_RUNTIME_FQDN}', 'medium', 'Running', '${VERSION:-unknown}', '${TARGET_SDDC_LCM_ID}');"
  LABEL="Fleet LCM: INSERT VSP cluster (${COMPONENT_ID})"
else
  VSP_SQL="UPDATE component SET sddc_lcm_id='${TARGET_SDDC_LCM_ID}', fqdn='${VCFA_RUNTIME_FQDN}', version='${VERSION:-unknown}'
           WHERE component_id='${COMPONENT_ID}';"
  LABEL="Fleet LCM: UPDATE VSP cluster (${COMPONENT_ID})"
fi

run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "$LABEL" "$VSP_SQL"

# =============================================================================
# Step 4: Register the VCFA component in the target SDDC LCM inventory and point
#         its Fleet LCM row at the target SDDC LCM (INSERT then delete any rows
#         pointing elsewhere, leaving a single target row).
# =============================================================================
step "Step 4: VCFA component re-home (the VCFA app component)"
VCFA_COUNT=$(q_fleet "SELECT COUNT(DISTINCT component_id) FROM component WHERE component_type='VCFA';")
if [[ "${VCFA_COUNT:-0}" -eq 0 ]]; then
  log "no VCFA component in Fleet LCM inventory — skipping"
elif [[ "${VCFA_COUNT}" -gt 1 ]]; then
  log "WARN found $VCFA_COUNT distinct VCFA component_ids (expected 1) — refusing to auto-move; handle manually"
else
  IFS='|' read -r VCFA_CID VCFA_VFQDN VCFA_VER VCFA_DEPLOY VCFA_SIZE VCFA_FLEET_ID <<< "$(q_fleet_row \
    "SELECT DISTINCT ON (component_id) component_id, fqdn, version, deployment_type, size, id
     FROM component WHERE component_type='VCFA' ORDER BY component_id LIMIT 1;")"
  VCFA_DEPLOY=${VCFA_DEPLOY:-VSP}; VCFA_SIZE=${VCFA_SIZE:-medium}
  VCFA_TGT=$(q_fleet   "SELECT COUNT(*) FROM component WHERE component_id='${VCFA_CID}' AND sddc_lcm_id='${TARGET_SDDC_LCM_ID}';")
  VCFA_STALE=$(q_fleet "SELECT COUNT(*) FROM component WHERE component_id='${VCFA_CID}' AND sddc_lcm_id<>'${TARGET_SDDC_LCM_ID}';")
  log "VCFA component_id: $VCFA_CID  (fqdn=$VCFA_VFQDN version=$VCFA_VER)"

  if [[ "${VCFA_TGT:-0}" -ge 1 && "${VCFA_STALE:-0}" -eq 0 ]]; then
    log "OK   VCFA already homed to target SDDC LCM only — nothing to do"
  else
    # 4a. SDDC LCM inventory: ensure a VCFA row exists (id = its Fleet LCM row id).
    VCFA_SDDC_EXISTS=$(q_sddc "SELECT COUNT(*) FROM component WHERE component_id='${VCFA_CID}';")
    if [[ "${VCFA_SDDC_EXISTS:-0}" -ge 1 ]]; then
      run_write "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" "SDDC LCM: refresh VCFA metadata" \
        "UPDATE component SET fqdn='${VCFA_VFQDN}', version='${VCFA_VER}' WHERE component_id='${VCFA_CID}';"
    else
      run_write "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" "SDDC LCM: INSERT VCFA ($VCFA_CID)" \
        "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version)
         VALUES ('${VCFA_FLEET_ID}', '${VCFA_CID}', 'VCFA', '${VCFA_DEPLOY}', '${VCFA_VFQDN}', '${VCFA_SIZE}', '${VCFA_VER}');"
    fi

    # 4b. Fleet LCM: create the target row if missing, then re-point config off
    #     rows pointing elsewhere before deleting them (component_config first,
    #     due to the FK constraint). The INSERT above only copies component's
    #     own columns, so the new target row starts with no config of its own -
    #     a plain DELETE here would leave VCFA registered but with its
    #     configuration entirely gone.
    if [[ "${VCFA_TGT:-0}" -ge 1 ]]; then
      log "OK   VCFA Fleet LCM target row already exists"
    else
      run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: INSERT VCFA row for target SDDC LCM" \
        "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version, sddc_lcm_id)
         SELECT ${UUIDV7_SQL}, '${VCFA_CID}', component_type, deployment_type, fqdn, size, version, '${TARGET_SDDC_LCM_ID}'
         FROM component WHERE component_id='${VCFA_CID}' LIMIT 1;"
    fi
    # Re-point config the target doesn't already have a (type) for, so config
    # genuinely already on the target row (e.g. from an earlier partial run)
    # is never clobbered by stale data.
    run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: RE-POINT VCFA component_config to target row" \
      "UPDATE component_config
       SET component_id = (
         SELECT id FROM component WHERE component_id='${VCFA_CID}' AND sddc_lcm_id='${TARGET_SDDC_LCM_ID}' LIMIT 1
       )
       WHERE component_id IN (
         SELECT id FROM component WHERE component_id='${VCFA_CID}' AND sddc_lcm_id<>'${TARGET_SDDC_LCM_ID}'
       )
       AND type NOT IN (
         SELECT type FROM component_config WHERE component_id = (
           SELECT id FROM component WHERE component_id='${VCFA_CID}' AND sddc_lcm_id='${TARGET_SDDC_LCM_ID}' LIMIT 1
         )
       );"
    # Anything left is stale config whose type already exists on the target
    # row (couldn't be re-pointed without a duplicate) - delete just that
    # leftover so fk_component_config_component doesn't block the row delete.
    run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE VCFA leftover conflicting component_config rows" \
      "DELETE FROM component_config WHERE component_id IN (
         SELECT id FROM component WHERE component_id='${VCFA_CID}' AND sddc_lcm_id<>'${TARGET_SDDC_LCM_ID}');"
    run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE VCFA stale rows (non-target SDDC LCMs)" \
      "DELETE FROM component WHERE component_id='${VCFA_CID}' AND sddc_lcm_id<>'${TARGET_SDDC_LCM_ID}';"
  fi
fi

# =============================================================================
# Step 4b: vcd-migrator component re-home. id/fqdn/version/size here always
#          come from Step 1's live query of the consumption cluster, never
#          from Fleet LCM DB - any pre-existing Fleet LCM row for it could be
#          stale from an earlier run. Skipped entirely if the live cluster
#          has no vcd-migrator component (not every consumption cluster has
#          one).
# =============================================================================
step "Step 4b: vcd-migrator component re-home"
if [[ -z "${VCD_MIGRATOR_ID:-}" ]]; then
  log "no vcd-migrator component on this cluster — skipping"
else
  # Purge stale Fleet LCM rows left under a DIFFERENT component_id. Unlike
  # VCFA/VSP, vcd-migrator's component_id is not stable across redeploys - a
  # fresh deployment gets a brand-new id - so the component_id-scoped cleanup
  # below (matching only the current live id) can't catch rows from an
  # earlier deployment under an old id. Mirrors Step 3's analogous purge for
  # the VSP cluster row (there, keyed on fqdn instead, since vcd-migrator has
  # no fqdn of its own to key on). Deleted in FK dependency order: node ->
  # component_config -> component.
  run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE stale vcd-migrator node rows under old component_ids" \
    "DELETE FROM node WHERE component_id IN (
       SELECT id FROM component WHERE component_type='VCD_MIGRATOR' AND component_id<>'${VCD_MIGRATOR_ID}');"
  run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE stale vcd-migrator config rows under old component_ids" \
    "DELETE FROM component_config WHERE component_id IN (
       SELECT id FROM component WHERE component_type='VCD_MIGRATOR' AND component_id<>'${VCD_MIGRATOR_ID}');"
  run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE stale vcd-migrator rows under old component_ids" \
    "DELETE FROM component WHERE component_type='VCD_MIGRATOR' AND component_id<>'${VCD_MIGRATOR_ID}';"

  VCDM_TGT=$(q_fleet   "SELECT COUNT(*) FROM component WHERE component_id='${VCD_MIGRATOR_ID}' AND sddc_lcm_id='${TARGET_SDDC_LCM_ID}';")
  VCDM_STALE=$(q_fleet "SELECT COUNT(*) FROM component WHERE component_id='${VCD_MIGRATOR_ID}' AND sddc_lcm_id<>'${TARGET_SDDC_LCM_ID}';")
  log "vcd-migrator component_id: $VCD_MIGRATOR_ID  (fqdn=${VCD_MIGRATOR_FQDN:-<none>} version=$VCD_MIGRATOR_VERSION)"

  if [[ "${VCDM_TGT:-0}" -ge 1 && "${VCDM_STALE:-0}" -eq 0 ]]; then
    log "OK   vcd-migrator already homed to target SDDC LCM only — nothing to do"
  else
    # 4b-a. SDDC LCM inventory: ensure a row exists, always refreshed to the live fqdn/version.
    VCDM_SDDC_EXISTS=$(q_sddc "SELECT COUNT(*) FROM component WHERE component_id='${VCD_MIGRATOR_ID}';")
    if [[ "${VCDM_SDDC_EXISTS:-0}" -ge 1 ]]; then
      run_write "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" "SDDC LCM: refresh vcd-migrator metadata" \
        "UPDATE component SET fqdn='${VCD_MIGRATOR_FQDN}', version='${VCD_MIGRATOR_VERSION}' WHERE component_id='${VCD_MIGRATOR_ID}';"
    else
      run_write "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" "SDDC LCM: INSERT vcd-migrator ($VCD_MIGRATOR_ID)" \
        "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version)
         VALUES (${UUIDV7_SQL}, '${VCD_MIGRATOR_ID}', 'VCD_MIGRATOR', 'VSP', '${VCD_MIGRATOR_FQDN}', '${VCD_MIGRATOR_SIZE}', '${VCD_MIGRATOR_VERSION}');"
    fi

    # 4b-b. Fleet LCM: create the target row (from live data) if missing, then
    #       re-point config off rows pointing elsewhere before deleting them -
    #       same rationale as Step 4's VCFA handling above.
    if [[ "${VCDM_TGT:-0}" -ge 1 ]]; then
      log "OK   vcd-migrator Fleet LCM target row already exists"
    else
      run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: INSERT vcd-migrator row for target SDDC LCM" \
        "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version, sddc_lcm_id)
         VALUES (${UUIDV7_SQL}, '${VCD_MIGRATOR_ID}', 'VCD_MIGRATOR', 'VSP', '${VCD_MIGRATOR_FQDN}', '${VCD_MIGRATOR_SIZE}', '${VCD_MIGRATOR_VERSION}', '${TARGET_SDDC_LCM_ID}');"
    fi
    run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: RE-POINT vcd-migrator component_config to target row" \
      "UPDATE component_config
       SET component_id = (
         SELECT id FROM component WHERE component_id='${VCD_MIGRATOR_ID}' AND sddc_lcm_id='${TARGET_SDDC_LCM_ID}' LIMIT 1
       )
       WHERE component_id IN (
         SELECT id FROM component WHERE component_id='${VCD_MIGRATOR_ID}' AND sddc_lcm_id<>'${TARGET_SDDC_LCM_ID}'
       )
       AND type NOT IN (
         SELECT type FROM component_config WHERE component_id = (
           SELECT id FROM component WHERE component_id='${VCD_MIGRATOR_ID}' AND sddc_lcm_id='${TARGET_SDDC_LCM_ID}' LIMIT 1
         )
       );"
    run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE vcd-migrator leftover conflicting component_config rows" \
      "DELETE FROM component_config WHERE component_id IN (
         SELECT id FROM component WHERE component_id='${VCD_MIGRATOR_ID}' AND sddc_lcm_id<>'${TARGET_SDDC_LCM_ID}');"
    run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE vcd-migrator stale rows (non-target SDDC LCMs)" \
      "DELETE FROM component WHERE component_id='${VCD_MIGRATOR_ID}' AND sddc_lcm_id<>'${TARGET_SDDC_LCM_ID}';"
  fi
fi

# =============================================================================
# Step 5: Create the VCFA service accounts (admin + adminextra) that VCFA
#         needs to register itself with VCF Operations. Without these,
#         VCFA-Ops registration always fails with NoSuchElementException
#         (CreateVcfaServiceAccountWorkflow). Only runs if step 4 found a
#         single VCFA component to register (VCFA_CID/VCFA_VFQDN set).
# =============================================================================
step "Step 5: VCFA service accounts for Ops registration"
if [[ -z "${VCFA_CID:-}" || -z "${VCFA_VFQDN:-}" ]]; then
  log "WARN no VCFA component found in step 4 — skipping"
else
  CREATE_SA_SCRIPT="$(dirname "$0")/create_vcfa_service_account.sh"
  if [[ ! -x "$CREATE_SA_SCRIPT" ]]; then
    log "WARN $CREATE_SA_SCRIPT not found/executable — skipping."
    log "     VCFA-Ops registration will fail without it; run it manually."
  else
    if [[ -z "$VCFA_SYSTEM_PASSWORD" ]]; then
      read -rs -p "admin@System password for VCFA (${VCFA_VFQDN}): " VCFA_SYSTEM_PASSWORD; echo
    fi
    STEP5_RC=0
    DRY_FLAG=(); $DRY_RUN && DRY_FLAG=(--dry-run)
    for ACCOUNT_TYPE in admin adminextra; do
      log "-- account-type=$ACCOUNT_TYPE --"
      "$CREATE_SA_SCRIPT" --vcfa-fqdn "$VCFA_VFQDN" --component-id "$VCFA_CID" \
        --account-type "$ACCOUNT_TYPE" \
        --admin-password "$VCFA_SYSTEM_PASSWORD" "${DRY_FLAG[@]}" 2>&1 | sed 's/^/  /'
      [[ ${PIPESTATUS[0]} -eq 0 ]] || STEP5_RC=1
    done
    [[ $STEP5_RC -eq 0 ]] || log "ERROR one or more service-account creations failed (see above)."
  fi
fi

# =============================================================================
# Step 6: Re-register VCFA with VCF Operations - delete its stale Ops
#         component record and trigger Fleet LCM to re-register it from
#         scratch. Via update_registration_in_ops.sh, which must sit next to
#         this script. Only skipped if step 4 found no VCFA component to
#         register (VCFA_CID unset); --ops-fqdn itself is required.
# =============================================================================
step "Step 6: Re-register VCFA with VCF Operations"
if [[ -z "${VCFA_CID:-}" ]]; then
  log "WARN no VCFA component found in step 4 — skipping"
else
  REG_OPS_SCRIPT="$(dirname "$0")/update_registration_in_ops.sh"
  if [[ ! -x "$REG_OPS_SCRIPT" ]]; then
    log "WARN $REG_OPS_SCRIPT not found/executable — skipping."
    log "     VCF Operations will keep a stale component record without it; run it manually."
  else
    if [[ -z "$OPS_PASSWORD" ]]; then
      read -rs -p "VCF Operations admin password for ${OPS_FQDN}: " OPS_PASSWORD; echo
    fi
    DRY_FLAG=(); $DRY_RUN && DRY_FLAG=(--dry-run)
    OPS_ADMIN_PASSWORD="$OPS_PASSWORD" \
      "$REG_OPS_SCRIPT" --ops-fqdn "$OPS_FQDN" --component-id "$VCFA_CID" "${DRY_FLAG[@]}" 2>&1 | sed 's/^/  /'
    STEP6_RC=${PIPESTATUS[0]}
    [[ $STEP6_RC -eq 0 ]] || log "ERROR step 6 (VCF Operations re-registration) failed (see above)."
  fi
fi

# =============================================================================
# Verify (read-only)
# =============================================================================
step "Verification (current state)"
echo "  -- SDDC LCM VSP components (should include the consumption FQDN) --"
"${KC[@]}" exec "$SDDC_DB_POD" -n "$SDDC_NS" -c postgres -- psql -U postgres -d "$SDDC_DB" \
  -c "SELECT component_id, fqdn FROM component WHERE component_type='VSP';" 2>/dev/null | sed 's/^/  /'
echo "  -- Fleet LCM row for the consumption VSP cluster --"
"${KC[@]}" exec "$FLEET_DB_POD" -n "$FLEET_NS" -c postgres -- psql -U postgres -d "$FLEET_DB" \
  -c "SELECT component_id, fqdn, sddc_lcm_id FROM component WHERE component_id='${COMPONENT_ID}';" 2>/dev/null | sed 's/^/  /'
echo "  -- VSP service-account secret in $SDDC_NS --"
"${KC[@]}" get secret -n "$SDDC_NS" -l "vcf.broadcom.com/component-type=vsp,vcf.broadcom.com/component-id=${COMPONENT_ID}" 2>/dev/null | sed 's/^/  /'
echo "  -- VCFA component (Fleet LCM: should be a single row at the target SDDC LCM) --"
"${KC[@]}" exec "$FLEET_DB_POD" -n "$FLEET_NS" -c postgres -- psql -U postgres -d "$FLEET_DB" \
  -c "SELECT component_type, component_id, fqdn, sddc_lcm_id FROM component WHERE component_type='VCFA';" 2>/dev/null | sed 's/^/  /'
echo "  -- VCFA component (SDDC LCM inventory) --"
"${KC[@]}" exec "$SDDC_DB_POD" -n "$SDDC_NS" -c postgres -- psql -U postgres -d "$SDDC_DB" \
  -c "SELECT component_type, component_id, fqdn, version FROM component WHERE component_type='VCFA';" 2>/dev/null | sed 's/^/  /'
if [[ -n "${VCFA_CID:-}" ]]; then
  echo "  -- VCFA service accounts for Ops registration (admin persists; adminextra is"
  echo "     consumed and deleted by SBS/FBS once registration succeeds - absent here"
  echo "     is expected once VCFA is already registered with VCF Operations) --"
  "${KC[@]}" get secrets -n "$SDDC_NS" -l "vcf.broadcom.com/component-type=vcfa,vcf.broadcom.com/component-id=${VCFA_CID}" 2>/dev/null | sed 's/^/  /'
fi
if [[ -n "${VCD_MIGRATOR_ID:-}" ]]; then
  echo "  -- vcd-migrator component (Fleet LCM: should be a single row at the target SDDC LCM) --"
  "${KC[@]}" exec "$FLEET_DB_POD" -n "$FLEET_NS" -c postgres -- psql -U postgres -d "$FLEET_DB" \
    -c "SELECT component_type, component_id, fqdn, sddc_lcm_id FROM component WHERE component_type='VCD_MIGRATOR';" 2>/dev/null | sed 's/^/  /'
  echo "  -- vcd-migrator component (SDDC LCM inventory) --"
  "${KC[@]}" exec "$SDDC_DB_POD" -n "$SDDC_NS" -c postgres -- psql -U postgres -d "$SDDC_DB" \
    -c "SELECT component_type, component_id, fqdn, version FROM component WHERE component_type='VCD_MIGRATOR';" 2>/dev/null | sed 's/^/  /'
fi

echo
echo "======================================================================"
$DRY_RUN && echo " DRY-RUN complete — no changes written." || echo " Repair complete."
echo " SDDC LCM re-discovers components on a ~15-min cycle; the VCF Ops"
echo " 'VCF Automation' config page should load within a cycle or two."
echo " If VCFA status stays 'Unknown', check sddc-build-service logs for the"
echo " next refresh of component ${COMPONENT_ID}."
[[ "${STEP5_RC:-0}" -ne 0 ]] && echo " WARNING: step 5 (VCFA service accounts) reported errors above - VCFA-Ops"
[[ "${STEP5_RC:-0}" -ne 0 ]] && echo "          registration will likely still fail until that is resolved."
[[ "${STEP6_RC:-0}" -ne 0 ]] && echo " WARNING: step 6 (VCF Operations re-registration) reported errors above -"
[[ "${STEP6_RC:-0}" -ne 0 ]] && echo "          VCF Operations will keep showing a stale component until resolved."
echo "======================================================================"

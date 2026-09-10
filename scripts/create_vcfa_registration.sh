#!/usr/bin/env bash
# =============================================================================
# create_vcfa_registration.sh
# Create VCFA and consumption VSP cluster registration on target VCF instance.
# =============================================================================
#
# Re-creates registration for the VCFA component and its consumption VSP cluster
# ("VCF services runtime") in target instance's SDDC LCM and Fleet LCM DBs.
#
# Steps:
#   1. Query consumption cluster API to fetch live VSP and VCFA metadata
#      (component IDs, FQDNs, versions, sizes) and store VSP admin secret in k8s.
#   2. Strictly validate live metadata resolved from API (zero DB queries).
#   3. Purge all existing VSP and VCFA records across all dependent tables in both
#      SDDC LCM and Fleet LCM databases.
#   4. Insert fresh, clean inventory entries for VSP and VCFA in both databases
#      using UUIDv7 primary keys.
#   5. Create the VCFA service accounts (admin + adminextra) needed for Ops registration.
#   6. Re-register VCFA with VCF Operations.
# =============================================================================

set -uo pipefail

# ---- configurable constants -------------------------------------------------
SDDC_NS="vcf-sddc-lcm"
FLEET_NS="vcf-fleet-lcm"
SDDC_DB="vcfsddclcmdb"
FLEET_DB="vcffleetlcmdb"
SDDC_DB_PREFIX="vcf-sddc-lcm-db"
FLEET_DB_PREFIX="vcf-fleet-lcm-db"
CLIENT_NAME="svc-sddclcm-vsp-admin"

UUIDV7_SQL="(WITH src AS (
  SELECT overlay(uuid_send(gen_random_uuid())
         placing substring(int8send(floor(extract(epoch from clock_timestamp())*1000)::bigint) from 3)
         from 1 for 6) AS b)
 SELECT encode(set_byte(set_byte(b,6,(get_byte(b,6)&15)|112),8,(get_byte(b,8)&63)|128),'hex')::uuid FROM src)"

# ---- args -------------------------------------------------------------------
VCFA_RUNTIME_FQDN=""
PASSWORD="${VCFA_ADMIN_PASSWORD:-}"
VCFA_SYSTEM_PASSWORD="${VCFA_SYSTEM_PASSWORD:-}"
OPS_FQDN=""
OPS_PASSWORD="${OPS_ADMIN_PASSWORD:-}"
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage:
  export KUBECONFIG=<target-DR-cluster-kubeconfig>
  ./create_vcfa_registration.sh --vcfa-runtime-fqdn <FQDN> --ops-fqdn <ops-fqdn> \
      [--password <pw>] [--vcfa-system-password <pw>] [--ops-password <pw>] \
      [--dry-run]

Purges old database entries for VSP and VCFA in SDDC LCM and Fleet LCM DBs,
creates fresh records for both components using live cluster API data,
and completes VCF Operations registration. Idempotent.

Options:
  --vcfa-runtime-fqdn FQDN   (required) FQDN of the VCFA consumption cluster.
  --ops-fqdn FQDN            (required) FQDN/IP of the VCF Operations appliance.
  --password PW              admin@vsp.local password for consumption cluster.
  --vcfa-system-password PW  admin@System password for VCFA application.
  --ops-password PW          VCF Operations admin password.
  --dry-run                  Preview database operations without applying.
  -h, --help                 Show help and exit.
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vcfa-runtime-fqdn)    VCFA_RUNTIME_FQDN="$2"; shift 2 ;;
    --password)             PASSWORD="$2"; shift 2 ;;
    --vcfa-system-password) VCFA_SYSTEM_PASSWORD="$2"; shift 2 ;;
    --ops-fqdn)              OPS_FQDN="$2"; shift 2 ;;
    --ops-password)          OPS_PASSWORD="$2"; shift 2 ;;
    --dry-run)              DRY_RUN=true; shift ;;
    -h|--help)             usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

[[ -n "$VCFA_RUNTIME_FQDN" ]] || { echo "ERROR: --vcfa-runtime-fqdn is required" >&2; usage 1; }
[[ -n "$OPS_FQDN" ]]         || { echo "ERROR: --ops-fqdn is required" >&2; usage 1; }
[[ -n "${KUBECONFIG:-}" ]]   || { echo "ERROR: KUBECONFIG is not set." >&2; exit 1; }

KC=(kubectl)

"${KC[@]}" get ns "$SDDC_NS" >/dev/null 2>&1 || {
  echo "ERROR: namespace '$SDDC_NS' not reachable via \$KUBECONFIG." >&2
  exit 1
}

if [[ -z "$PASSWORD" ]]; then
  read -rs -p "admin@vsp.local password for ${VCFA_RUNTIME_FQDN}: " PASSWORD; echo
fi
[[ -n "$PASSWORD" ]] || { echo "ERROR: password is empty" >&2; exit 1; }

log()  { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

echo "======================================================================"
echo " Create VCFA + VSP cluster registration on target VCF instance"
echo " VCFA runtime FQDN : $VCFA_RUNTIME_FQDN"
echo " KUBECONFIG        : $KUBECONFIG"
$DRY_RUN && echo " *** DRY-RUN: no changes will be written ***"
echo "======================================================================"

# ---- locate pods ------------------------------------------------------------
step "Step 0: Locating pods on target cluster"
SBS_POD=$("${KC[@]}" get pods -n "$SDDC_NS" -o name 2>/dev/null | grep -m1 'sddc-build-service' | cut -d/ -f2)
[[ -n "$SBS_POD" ]] || { echo "ERROR: could not find sddc-build-service pod in $SDDC_NS" >&2; exit 1; }
log "sddc-build-service pod: $SBS_POD"

find_primary() {
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

q_sddc()  { "${KC[@]}" exec "$SDDC_DB_POD"  -n "$SDDC_NS"  -c postgres -- psql -U postgres -d "$SDDC_DB"  -t -A -c "$1" 2>/dev/null | tr -d '[:space:]'; }
q_fleet() { "${KC[@]}" exec "$FLEET_DB_POD" -n "$FLEET_NS" -c postgres -- psql -U postgres -d "$FLEET_DB" -t -A -c "$1" 2>/dev/null | tr -d '[:space:]'; }

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

TARGET_SDDC_LCM_ID=$(q_sddc "SELECT component_id FROM component WHERE component_type='VCF_SDDC_LCM' LIMIT 1;")
[[ -n "$TARGET_SDDC_LCM_ID" ]] || { echo "ERROR: could not determine target SDDC LCM id" >&2; exit 1; }
log "target SDDC LCM id  : $TARGET_SDDC_LCM_ID"

# =============================================================================
# Step 1: Query VSP & VCFA metadata from live cluster API + create secret
# =============================================================================
step "Step 1: Fetch live VSP & VCFA metadata from cluster API (runs inside $SBS_POD)"

POD_SCRIPT='
  read -r PW; read -r FQDN; read -r NS; read -r CN; read -r DRY
  BASE="https://$FQDN/api/v1"
  TR=$(curl -sk "$BASE/identity/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode grant_type=password \
        --data-urlencode "username=admin@vsp.local" \
        --data-urlencode "password=$PW")
  TOKEN=$(printf "%s" "$TR" | sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p")
  [ -n "$TOKEN" ] || { echo "ERR token: $(printf "%s" "$TR" | head -c 140)"; exit 3; }

  # Query VSP component metadata & size
  CJ_VSP=$(curl -sk "$BASE/components?type=vsp" -H "Authorization: Bearer $TOKEN")
  OBJ_VSP=$(printf "%s" "$CJ_VSP" | sed "s/},{/}\n{/g" | grep -F "\"fqdn\":\"$FQDN\"" | head -1)
  [ -n "$OBJ_VSP" ] || { echo "ERR no vsp component with fqdn=$FQDN: $(printf "%s" "$CJ_VSP" | head -c 160)"; exit 3; }
  COMP_VSP=$(printf "%s" "$OBJ_VSP" | sed -n "s/.*\"id\":\"\([^\"]*\)\".*/\1/p" | head -1)
  [ -n "$COMP_VSP" ] || { echo "ERR could not extract VSP id for fqdn=$FQDN"; exit 3; }
  VER_VSP=$(printf "%s" "$OBJ_VSP" | grep -oE "\"version\":\"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[^\"]*\"" | head -1 | sed "s/.*:\"//;s/\"//")
  SIZE_VSP=$(printf "%s" "$OBJ_VSP" | sed -n "s/.*\"size\":\"\([^\"]*\)\".*/\1/p" | head -1)

  # Query VCFA component metadata & size directly from VSP cluster API
  CJ_VCFA=$(curl -sk "$BASE/components?type=vcfa" -H "Authorization: Bearer $TOKEN")
  OBJ_VCFA=$(printf "%s" "$CJ_VCFA" | sed "s/},{/}\n{/g" | head -1)
  COMP_VCFA=$(printf "%s" "$OBJ_VCFA" | sed -n "s/.*\"id\":\"\([^\"]*\)\".*/\1/p" | head -1)
  FQDN_VCFA=$(printf "%s" "$OBJ_VCFA" | sed -n "s/.*\"fqdn\":\"\([^\"]*\)\".*/\1/p" | head -1)
  VER_VCFA=$(printf "%s" "$OBJ_VCFA" | grep -oE "\"version\":\"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[^\"]*\"" | head -1 | sed "s/.*:\"//;s/\"//")
  SIZE_VCFA=$(printf "%s" "$OBJ_VCFA" | sed -n "s/.*\"size\":\"\([^\"]*\)\".*/\1/p" | head -1)

  echo "COMPONENT_ID=$COMP_VSP"
  echo "VERSION=${VER_VSP:-unknown}"
  echo "VSP_SIZE=${SIZE_VSP:-medium}"
  echo "VCFA_CID=$COMP_VCFA"
  echo "VCFA_VFQDN=${FQDN_VCFA}"
  echo "VCFA_VER=${VER_VCFA:-unknown}"
  echo "VCFA_SIZE=${SIZE_VCFA:-medium}"

  # Create VSP IAM Secret in K8s
  KTOK=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  CACRT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  KAPI=https://kubernetes.default.svc
  EXIST=$(curl -sk "$KAPI/api/v1/namespaces/$NS/secrets?labelSelector=vcf.broadcom.com/component-type%3Dvsp,vcf.broadcom.com/component-id%3D$COMP_VSP" --cacert "$CACRT" -H "Authorization: Bearer $KTOK" | grep -c "\"name\"")
  if [ "${EXIST:-0}" -ge 1 ]; then echo "SA_SECRET=exists"; exit 0; fi
  if [ "$DRY" = "true" ]; then echo "SA_SECRET=would-create"; exit 0; fi
  BODY="{\"clientName\":\"$CN\",\"componentType\":\"vsp\",\"componentId\":\"$COMP_VSP\",\"accessTokenTtl\":14440,\"roles\":[{\"name\":\"admin\",\"type\":\"vsp\"}]}"
  HC=$(printf "%s" "$BODY" | curl -sk -o /tmp/sar.$$ -w "%{http_code}" -X POST "$BASE/identity/service-accounts" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @-)
  if [ "$HC" != "201" ]; then echo "ERR create-SA HTTP $HC: $(head -c 160 /tmp/sar.$$)"; rm -f /tmp/sar.$$; exit 3; fi
  NCID=$(sed -n "s/.*\"clientId\":\"\([^\"]*\)\".*/\1/p" /tmp/sar.$$)
  NCS=$(sed -n "s/.*\"clientSecret\":\"\([^\"]*\)\".*/\1/p" /tmp/sar.$$)
  rm -f /tmp/sar.$$
  [ -n "$NCS" ] || { echo "ERR no clientSecret returned"; exit 3; }
  B64ID=$(printf "%s" "$NCID" | base64 | tr -d "\n")
  B64CS=$(printf "%s" "$NCS" | base64 | tr -d "\n")
  SNAME="vcf-iam-vsp-$CN-$COMP_VSP"
  SEC="{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"type\":\"Opaque\",\"metadata\":{\"name\":\"$SNAME\",\"labels\":{\"app.kubernetes.io/managed-by\":\"vcf-identity-library\",\"vcf.broadcom.com/component-type\":\"vsp\",\"vcf.broadcom.com/component-id\":\"$COMP_VSP\",\"vcf.broadcom.com/client-name\":\"$CN\"}},\"data\":{\"clientId\":\"$B64ID\",\"clientSecret\":\"$B64CS\"}}"
  KHC=$(printf "%s" "$SEC" | curl -sk -o /tmp/kr.$$ -w "%{http_code}" -X POST "$KAPI/api/v1/namespaces/$NS/secrets" --cacert "$CACRT" -H "Authorization: Bearer $KTOK" -H "Content-Type: application/json" -d @-)
  if [ "$KHC" != "201" ]; then echo "ERR create-secret HTTP $KHC: $(head -c 160 /tmp/kr.$$)"; rm -f /tmp/kr.$$; exit 3; fi
  rm -f /tmp/kr.$$
  echo "SA_SECRET=created:$SNAME"
'

POD_OUT=$(printf '%s\n%s\n%s\n%s\n%s\n' "$PASSWORD" "$VCFA_RUNTIME_FQDN" "$SDDC_NS" "$CLIENT_NAME" "$DRY_RUN" \
          | "${KC[@]}" exec -n "$SDDC_NS" -i "$SBS_POD" -- sh -c "$POD_SCRIPT" 2>&1)
POD_RC=$?
printf '%s\n' "$POD_OUT" | grep -v '^COMPONENT_ID=\|^VERSION=\|^VSP_SIZE=\|^VCFA_CID=\|^VCFA_VFQDN=\|^VCFA_VER=\|^VCFA_SIZE=' | sed 's/^/  /'
if [[ $POD_RC -ne 0 ]]; then echo "ERROR: step 1 failed (see above)"; exit 1; fi

COMPONENT_ID=$(printf '%s\n' "$POD_OUT" | sed -n 's/^COMPONENT_ID=//p' | head -1)
VERSION=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VERSION=//p' | head -1)
VSP_SIZE=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VSP_SIZE=//p' | head -1)
VCFA_CID=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VCFA_CID=//p' | head -1)
VCFA_VFQDN=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VCFA_VFQDN=//p' | head -1)
VCFA_VER=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VCFA_VER=//p' | head -1)
VCFA_SIZE=$(printf '%s\n' "$POD_OUT" | sed -n 's/^VCFA_SIZE=//p' | head -1)

# =============================================================================
# Step 2: Validate live resolved metadata (strict validation, zero DB queries)
# =============================================================================
step "Step 2: Live metadata resolved from cluster API"

VSP_SIZE=${VSP_SIZE:-medium}
VCFA_SIZE=${VCFA_SIZE:-medium}
VCFA_DEPLOY="VSP"

[[ -n "$COMPONENT_ID" ]] || { echo "ERROR: could not obtain VSP component_id from cluster API"; exit 1; }
[[ -n "$VCFA_CID" ]]      || { echo "ERROR: could not obtain VCFA component_id from cluster API"; exit 1; }
[[ -n "$VCFA_VFQDN" ]]    || { echo "ERROR: could not obtain VCFA fqdn from cluster API"; exit 1; }

log "VSP  component_id: $COMPONENT_ID (fqdn=$VCFA_RUNTIME_FQDN, version=${VERSION:-unknown}, size=$VSP_SIZE)"
log "VCFA component_id: $VCFA_CID (fqdn=$VCFA_VFQDN, version=$VCFA_VER, size=$VCFA_SIZE)"

# =============================================================================
# Step 3: Purge old VSP and VCFA records from Fleet LCM DB and SDDC LCM DB
# =============================================================================
step "Step 3: Purging old VSP and VCFA records across all database tables"

# 3a. Fleet LCM DB Purge (Reverse FK Order: node -> component_config -> component)
run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE dependent node rows" \
  "DELETE FROM node WHERE component_id IN (
     SELECT id FROM component WHERE component_id IN ('${COMPONENT_ID}', '${VCFA_CID}')
        OR fqdn IN ('${VCFA_RUNTIME_FQDN}', '${VCFA_VFQDN}')
   );"

run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE dependent component_config rows" \
  "DELETE FROM component_config WHERE component_id IN (
     SELECT id FROM component WHERE component_id IN ('${COMPONENT_ID}', '${VCFA_CID}')
        OR fqdn IN ('${VCFA_RUNTIME_FQDN}', '${VCFA_VFQDN}')
   );"

run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: DELETE VSP and VCFA component rows" \
  "DELETE FROM component WHERE component_id IN ('${COMPONENT_ID}', '${VCFA_CID}')
     OR fqdn IN ('${VCFA_RUNTIME_FQDN}', '${VCFA_VFQDN}');"

# 3b. SDDC LCM DB Purge (Reverse FK Order: node -> component)
run_write "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" "SDDC LCM: DELETE dependent node rows" \
  "DELETE FROM node WHERE component_id IN (
     SELECT id FROM component WHERE component_id IN ('${COMPONENT_ID}', '${VCFA_CID}')
        OR fqdn IN ('${VCFA_RUNTIME_FQDN}', '${VCFA_VFQDN}')
   );"

run_write "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" "SDDC LCM: DELETE VSP and VCFA component rows" \
  "DELETE FROM component WHERE component_id IN ('${COMPONENT_ID}', '${VCFA_CID}')
     OR fqdn IN ('${VCFA_RUNTIME_FQDN}', '${VCFA_VFQDN}');"

# =============================================================================
# Step 4: Create fresh LCM inventory entries for VSP and VCFA
# =============================================================================
step "Step 4: Creating fresh VSP and VCFA entries in SDDC LCM and Fleet LCM DBs"

# Pre-generate primary keys (UUIDv7)
VSP_SDDC_ID=$(q_sddc "SELECT ${UUIDV7_SQL};")
VSP_FLEET_ID=$(q_fleet "SELECT ${UUIDV7_SQL};")
VCFA_PRIMARY_ID=$(q_fleet "SELECT ${UUIDV7_SQL};")

# 4a. SDDC LCM DB Insertions
run_write "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" "SDDC LCM: INSERT VSP component (${COMPONENT_ID})" \
  "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version)
   VALUES ('${VSP_SDDC_ID}', '${COMPONENT_ID}', 'VSP', 'VSP', '${VCFA_RUNTIME_FQDN}', '${VSP_SIZE}', '${VERSION:-unknown}');"

run_write "$SDDC_NS" "$SDDC_DB_POD" "$SDDC_DB" "SDDC LCM: INSERT VCFA component (${VCFA_CID})" \
  "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version)
   VALUES ('${VCFA_PRIMARY_ID}', '${VCFA_CID}', 'VCFA', '${VCFA_DEPLOY}', '${VCFA_VFQDN}', '${VCFA_SIZE}', '${VCFA_VER}');"

# 4b. Fleet LCM DB Insertions
run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: INSERT VSP component (${COMPONENT_ID})" \
  "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, status, version, sddc_lcm_id)
   VALUES ('${VSP_FLEET_ID}', '${COMPONENT_ID}', 'VSP', 'VSP', '${VCFA_RUNTIME_FQDN}', '${VSP_SIZE}', 'Running', '${VERSION:-unknown}', '${TARGET_SDDC_LCM_ID}');"

run_write "$FLEET_NS" "$FLEET_DB_POD" "$FLEET_DB" "Fleet LCM: INSERT VCFA component (${VCFA_CID})" \
  "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, status, version, sddc_lcm_id)
   VALUES ('${VCFA_PRIMARY_ID}', '${VCFA_CID}', 'VCFA', '${VCFA_DEPLOY}', '${VCFA_VFQDN}', '${VCFA_SIZE}', 'Running', '${VCFA_VER}', '${TARGET_SDDC_LCM_ID}');"

# =============================================================================
# Step 5: Create VCFA service accounts for VCF Operations registration
# =============================================================================
step "Step 5: VCFA service accounts for Ops registration"
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

# =============================================================================
# Step 6: Re-register VCFA with VCF Operations
# =============================================================================
step "Step 6: Re-register VCFA with VCF Operations"
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

# =============================================================================
# Verification (read-only)
# =============================================================================
step "Verification (current state)"
echo "  -- SDDC LCM VSP & VCFA components --"
"${KC[@]}" exec "$SDDC_DB_POD" -n "$SDDC_NS" -c postgres -- psql -U postgres -d "$SDDC_DB" \
  -c "SELECT id, component_id, component_type, fqdn, size, version FROM component WHERE component_type IN ('VSP', 'VCFA');" 2>/dev/null | sed 's/^/  /'

echo "  -- Fleet LCM VSP & VCFA components --"
"${KC[@]}" exec "$FLEET_DB_POD" -n "$FLEET_NS" -c postgres -- psql -U postgres -d "$FLEET_DB" \
  -c "SELECT id, component_id, component_type, fqdn, size, sddc_lcm_id FROM component WHERE component_type IN ('VSP', 'VCFA');" 2>/dev/null | sed 's/^/  /'

echo "  -- VSP service-account secret in $SDDC_NS --"
"${KC[@]}" get secret -n "$SDDC_NS" -l "vcf.broadcom.com/component-type=vsp,vcf.broadcom.com/component-id=${COMPONENT_ID}" 2>/dev/null | sed 's/^/  /'

if [[ -n "${VCFA_CID:-}" ]]; then
  echo "  -- VCFA service accounts in $SDDC_NS --"
  "${KC[@]}" get secrets -n "$SDDC_NS" -l "vcf.broadcom.com/component-type=vcfa,vcf.broadcom.com/component-id=${VCFA_CID}" 2>/dev/null | sed 's/^/  /'
fi

echo
echo "======================================================================"
$DRY_RUN && echo " DRY-RUN complete — no changes written." || echo " Creation & registration complete."
echo "======================================================================"
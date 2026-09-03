#!/usr/bin/env bash
# =============================================================================
# Create a VCFA service account and store it as a vcf-iam-vcfa-* secret in
# vcf-sddc-lcm.
#
# Two account types (--account-type):
#   admin        SBS's own login to VCFA (client-name=admin). Used by things
#                like PropagateFdsDataToVcfaAction / PropagateSddcMgrData...
#   adminextra   The OPS_SR account (client-name=adminextra) that
#                CreateVcfaServiceAccountWorkflow.execute() looks up when
#                registering the VCFA component with VCF Operations. Without
#                it, that step throws NoSuchElementException.
#
# If neither vcf-iam-vcfa-admin nor vcf-iam-vcfa-adminextra exists yet (e.g.
# no DR backup to restore), run this script twice, once per --account-type,
# both with --admin-password - it doesn't depend on either secret existing.
#
# Runs entirely inside the sddc-build-service pod, which is the only pod with
# network reach to both the VCFA app FQDN and the in-cluster K8s API. No
# secret ever leaves the pod or appears in this script's own output.
#
# Bootstraps a VCFA bearer token one of two ways:
#   --admin-password / $VCFA_ADMIN_PASSWORD   admin@System login (simplest;
#                                              works with nothing pre-existing)
#   (neither given)                           reuse the existing
#                                              vcf-iam-vcfa-admin secret's
#                                              refresh token, if present
#
# Run with -h/--help for full usage. Set KUBECONFIG to the target cluster
# before running. Use --dry-run to preview without applying.
# =============================================================================

set -uo pipefail   # deliberately NOT -e: `read` returns 1 at EOF and would abort.

NAMESPACE="vcf-sddc-lcm"

VCFA_FQDN=""
COMPONENT_ID=""
ACCOUNT_TYPE=""
ADMIN_PASSWORD="${VCFA_ADMIN_PASSWORD:-}"
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage:
  export KUBECONFIG=<target-cluster-kubeconfig>
  ./create_vcfa_service_account.sh --vcfa-fqdn <FQDN> --component-id <UUID> \
      --account-type <admin|adminextra> [--admin-password <pw>] [--dry-run]

Creates a VCFA service account and stores it as a vcf-iam-vcfa-* secret in
vcf-sddc-lcm. Idempotent: does nothing if that secret already exists.

Options:
  --vcfa-fqdn FQDN       (required) The VCFA app's own FQDN (its Tenant
                         Manager API), e.g. inst1-vcfa.fst.com. Not the
                         consumption/runtime FQDN.
  --component-id UUID   (required) The VCFA component's id in SDDC LCM's
                         inventory, e.g. c30cac8a-f1d3-44e7-bb06-46b56d77489d.
  --account-type TYPE   (required) "admin" (SBS's own VCFA login) or
                         "adminextra" (the OPS_SR account needed to register
                         VCFA with VCF Operations).
  --admin-password PW   admin@System password for the VCFA app. If omitted,
                         taken from $VCFA_ADMIN_PASSWORD, else falls back to
                         reusing the existing vcf-iam-vcfa-admin secret's
                         refresh token (must already exist in vcf-sddc-lcm -
                         so it cannot be used to create the "admin" account
                         itself the first time; pass --admin-password then).
                         Never echoed; passed to the pod via stdin.
  --dry-run              Show what would be done without making changes.
  -h, --help              Show this help and exit.

Environment:
  KUBECONFIG             (required) Must be set before running and must
                          point to the cluster whose vcf-sddc-lcm namespace
                          you're fixing. Used for all kubectl access.

Examples:
  export KUBECONFIG=~/Downloads/inst2.kubeconfig

  # nothing pre-exists (no DR backup) - create both, in either order
  ./create_vcfa_service_account.sh --vcfa-fqdn inst1-vcfa.fst.com \
      --component-id c30cac8a-f1d3-44e7-bb06-46b56d77489d \
      --account-type admin --admin-password '...'
  ./create_vcfa_service_account.sh --vcfa-fqdn inst1-vcfa.fst.com \
      --component-id c30cac8a-f1d3-44e7-bb06-46b56d77489d \
      --account-type adminextra --admin-password '...'

  # vcf-iam-vcfa-admin already exists - bootstrap adminextra from it instead
  ./create_vcfa_service_account.sh --vcfa-fqdn inst1-vcfa.fst.com \
      --component-id c30cac8a-f1d3-44e7-bb06-46b56d77489d \
      --account-type adminextra
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vcfa-fqdn)      VCFA_FQDN="$2"; shift 2 ;;
    --component-id)   COMPONENT_ID="$2"; shift 2 ;;
    --account-type)   ACCOUNT_TYPE="$2"; shift 2 ;;
    --admin-password) ADMIN_PASSWORD="$2"; shift 2 ;;
    --dry-run)        DRY_RUN=true; shift ;;
    -h|--help)        usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

[[ -n "$VCFA_FQDN" ]] || { echo "ERROR: --vcfa-fqdn is required" >&2; usage 1; }
[[ -n "$COMPONENT_ID" ]] || { echo "ERROR: --component-id is required" >&2; usage 1; }
case "$ACCOUNT_TYPE" in
  admin)      SVC_PREFIX="svc-vcf-sddc-lcm-vcfa"; SECRET_NAME="vcf-iam-vcfa-admin";      CLIENT_LABEL="admin" ;;
  adminextra) SVC_PREFIX="svc-opssr-vcfa";        SECRET_NAME="vcf-iam-vcfa-adminextra"; CLIENT_LABEL="adminextra" ;;
  *) echo "ERROR: --account-type must be 'admin' or 'adminextra'" >&2; usage 1 ;;
esac
[[ -n "${KUBECONFIG:-}" ]] || { echo "ERROR: KUBECONFIG is not set. Export it before running." >&2; exit 1; }

KC=(kubectl)

"${KC[@]}" get ns "$NAMESPACE" >/dev/null 2>&1 || {
  echo "ERROR: namespace '$NAMESPACE' not reachable via \$KUBECONFIG ($KUBECONFIG)." >&2
  exit 1
}

MODE="secret"
if [[ -n "$ADMIN_PASSWORD" ]]; then
  MODE="password"
elif [[ "$ACCOUNT_TYPE" == "admin" ]]; then
  echo "ERROR: --account-type admin has nothing to bootstrap from - pass --admin-password." >&2
  exit 1
else
  echo "No --admin-password given; will bootstrap from the existing vcf-iam-vcfa-admin secret." >&2
fi

echo "======================================================================"
echo " Create VCFA service account"
echo " VCFA FQDN     : $VCFA_FQDN"
echo " Component id  : $COMPONENT_ID"
echo " Account type  : $ACCOUNT_TYPE ($SECRET_NAME, client-name=$CLIENT_LABEL)"
echo " Bootstrap mode: $MODE"
$DRY_RUN && echo " *** DRY-RUN: no changes will be written ***"
echo "======================================================================"

SBS_POD=$("${KC[@]}" get pods -n "$NAMESPACE" -o name 2>/dev/null | grep -m1 'sddc-build-service' | cut -d/ -f2)
[[ -n "$SBS_POD" ]] || { echo "ERROR: could not find sddc-build-service pod in $NAMESPACE" >&2; exit 1; }
echo "sddc-build-service pod: $SBS_POD"

# The device-authorization grant, once approved, cannot be re-issued for the
# same VCFA account - so register -> device_authorization -> grant -> token
# exchange must all happen in this ONE pod invocation, not split across calls.
POD_SCRIPT='
  read -r VCFA
  read -r COMPID
  read -r MODE
  read -r SECRET_ARG
  read -r DRY
  read -r SVC_PREFIX
  read -r SECRET_NAME
  read -r CLIENT_LABEL

  VER="application/json;version=40.0"
  KTOK=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  CACRT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  KAPI=https://kubernetes.default.svc
  NS=vcf-sddc-lcm

  EXIST=$(curl -sk "$KAPI/api/v1/namespaces/$NS/secrets?labelSelector=vcf.broadcom.com/component-type%3Dvcfa,vcf.broadcom.com/client-name%3D$CLIENT_LABEL" \
          --cacert "$CACRT" -H "Authorization: Bearer $KTOK" | grep -c "\"name\"")
  if [ "${EXIST:-0}" -ge 1 ]; then echo "$SECRET_NAME already exists - nothing to do"; exit 0; fi
  if [ "$DRY" = "true" ]; then echo "[DRY-RUN] would create $SECRET_NAME"; exit 0; fi

  if [ "$MODE" = "password" ]; then
    HDRS=$(curl -sk -D - -o /dev/null -X POST "https://$VCFA/tm/cloudapi/1.0.0/sessions/provider" \
      -u "admin@System:$SECRET_ARG" -H "Accept: $VER" -H "Content-Type: application/json")
    TOKEN=$(printf "%s" "$HDRS" | grep -i "^x-vmware-vcloud-access-token:" | sed "s/^[^:]*:[[:space:]]*//" | tr -d "\r")
  else
    S=$(curl -sk "$KAPI/api/v1/namespaces/$NS/secrets/vcf-iam-vcfa-admin" --cacert "$CACRT" -H "Authorization: Bearer $KTOK")
    ADMIN_CS=$(printf "%s" "$S" | tr "," "\n" | grep "\"clientSecret\"" | sed "s/.*\"clientSecret\"[: ]*\"//; s/\".*//" | base64 -d)
    [ -n "$ADMIN_CS" ] || { echo "ERR: vcf-iam-vcfa-admin secret not found - pass --admin-password instead"; exit 3; }
    TOKEN=$(curl -sk -X POST "https://$VCFA/tm/oauth/provider/token" -H "Accept: $VER" \
      --data-urlencode "refresh_token=$ADMIN_CS" --data-urlencode "grant_type=refresh_token" \
      | sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p")
  fi
  [ -n "$TOKEN" ] || { echo "ERR: could not obtain a VCFA bearer token (mode=$MODE)"; exit 3; }
  echo "[0] VCFA bearer acquired (mode=$MODE): OK"

  HEX=$(head -c2 /dev/urandom | od -An -tx1 | tr -d " \n" | cut -c1-3)
  SVC_NAME="$SVC_PREFIX-$HEX"
  SOFT_ID=$(cat /proc/sys/kernel/random/uuid)
  REG=$(curl -sk -X POST "https://$VCFA/tm/oauth/provider/register" \
    -H "Authorization: Bearer $TOKEN" -H "Accept: $VER" -H "Content-Type: application/json" \
    -d "{\"client_name\":\"$SVC_NAME\",\"software_id\":\"$SOFT_ID\",\"scope\":\"urn:vcloud:role:System%20Administrator\",\"client_uri\":\"https://www.vmware.com\",\"software_version\":\"1.0\"}")
  NEW_CID=$(printf "%s" "$REG" | sed -n "s/.*\"client_id\":\"\([^\"]*\)\".*/\1/p")
  [ -n "$NEW_CID" ] || { echo "ERR register: $(printf "%s" "$REG" | head -c 200)"; exit 3; }
  echo "[1] registered $SVC_NAME -> clientId=$NEW_CID"

  DA=$(curl -sk -X POST "https://$VCFA/tm/oauth/provider/device_authorization" \
    -H "Authorization: Bearer $TOKEN" -H "Accept: $VER" --data-urlencode "client_id=$NEW_CID")
  USER_CODE=$(printf "%s" "$DA" | sed -n "s/.*\"user_code\":\"\([^\"]*\)\".*/\1/p")
  DEVICE_CODE=$(printf "%s" "$DA" | sed -n "s/.*\"device_code\":\"\([^\"]*\)\".*/\1/p")
  if [ -z "$USER_CODE" ] || [ -z "$DEVICE_CODE" ]; then
    echo "ERR device_authorization: $(printf "%s" "$DA" | head -c 200)"
    curl -sk -o /dev/null -X DELETE "https://$VCFA/tm/cloudapi/1.0.0/serviceAccounts/urn:vcloud:serviceAccount:$NEW_CID" -H "Authorization: Bearer $TOKEN" -H "Accept: $VER"
    exit 3
  fi

  GRANTCODE=$(curl -sk -o /tmp/g.$$ -w "%{http_code}" -X POST "https://$VCFA/tm/cloudapi/1.0.0/deviceLookup/grant" \
    -H "Authorization: Bearer $TOKEN" -H "Accept: $VER" -H "Content-Type: application/json" \
    -d "{\"userCode\": \"$USER_CODE\"}")
  if [ "$GRANTCODE" != "204" ]; then
    echo "ERR grant HTTP $GRANTCODE: $(cat /tmp/g.$$ | head -c 200)"; rm -f /tmp/g.$$
    curl -sk -o /dev/null -X DELETE "https://$VCFA/tm/cloudapi/1.0.0/serviceAccounts/urn:vcloud:serviceAccount:$NEW_CID" -H "Authorization: Bearer $TOKEN" -H "Accept: $VER"
    exit 3
  fi
  rm -f /tmp/g.$$
  echo "[2] device_authorization + grant: OK"

  FINAL=$(curl -sk -X POST "https://$VCFA/tm/oauth/provider/token" \
    -H "Authorization: Bearer $TOKEN" -H "Accept: $VER" \
    --data-urlencode "client_id=$NEW_CID" --data-urlencode "device_code=$DEVICE_CODE" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code")
  NEW_REFRESH=$(printf "%s" "$FINAL" | sed -n "s/.*\"refresh_token\":\"\([^\"]*\)\".*/\1/p")
  [ -n "$NEW_REFRESH" ] || { echo "ERR token exchange: $(printf "%s" "$FINAL" | head -c 200)"; exit 3; }
  echo "[3] refresh token issued: OK"

  SA_JSON=$(curl -sk "https://$VCFA/tm/cloudapi/1.0.0/serviceAccounts/urn:vcloud:serviceAccount:$NEW_CID" \
    -H "Authorization: Bearer $TOKEN" -H "Accept: $VER")
  SA_JSON_MOD=$(printf "%s" "$SA_JSON" | sed "s/\"requireRotation\":true/\"requireRotation\":false/")
  PUTCODE=$(curl -sk -o /tmp/p.$$ -w "%{http_code}" -X PUT \
    "https://$VCFA/tm/cloudapi/1.0.0/serviceAccounts/urn:vcloud:serviceAccount:$NEW_CID" \
    -H "Authorization: Bearer $TOKEN" -H "Accept: $VER" -H "Content-Type: application/json" \
    -d "$SA_JSON_MOD")
  echo "[4] requireRotation=false -> HTTP $PUTCODE"
  rm -f /tmp/p.$$

  B64ID=$(printf "%s" "$NEW_CID" | base64 | tr -d "\n")
  B64CS=$(printf "%s" "$NEW_REFRESH" | base64 | tr -d "\n")
  SEC="{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"type\":\"Opaque\",\"metadata\":{\"name\":\"$SECRET_NAME\",\"labels\":{\"app.kubernetes.io/managed-by\":\"vcf-identity-library\",\"vcf.broadcom.com/component-type\":\"vcfa\",\"vcf.broadcom.com/component-id\":\"$COMPID\",\"vcf.broadcom.com/client-name\":\"$CLIENT_LABEL\"}},\"data\":{\"clientId\":\"$B64ID\",\"clientSecret\":\"$B64CS\"}}"
  KHC=$(printf "%s" "$SEC" | curl -sk -o /tmp/k.$$ -w "%{http_code}" -X POST "$KAPI/api/v1/namespaces/$NS/secrets" \
    --cacert "$CACRT" -H "Authorization: Bearer $KTOK" -H "Content-Type: application/json" -d @-)
  if [ "$KHC" = "201" ]; then
    echo "[5] created k8s secret $SECRET_NAME (clientId=$NEW_CID)"
  else
    echo "[5] ERR create-secret HTTP $KHC: $(head -c 200 /tmp/k.$$)"
  fi
  rm -f /tmp/k.$$
'

printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
  "$VCFA_FQDN" "$COMPONENT_ID" "$MODE" "$ADMIN_PASSWORD" "$DRY_RUN" "$SVC_PREFIX" "$SECRET_NAME" "$CLIENT_LABEL" \
  | "${KC[@]}" exec -n "$NAMESPACE" -i "$SBS_POD" -- sh -c "$POD_SCRIPT"
POD_RC=$?

echo "======================================================================"
if [[ $POD_RC -ne 0 ]]; then
  echo " FAILED - see output above."
  exit 1
fi
$DRY_RUN && echo " DRY-RUN complete - no changes written." || echo " Done."
echo "======================================================================"

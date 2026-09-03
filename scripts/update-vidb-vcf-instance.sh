#!/bin/bash
# =============================================================================
# update-vidb-vcf-instance.sh
#
# Disaster Recovery script: re-associates an external VIDB with a new VCF
# instance in VCF Operations via a PUT update, updates the collector, then
# waits for eligibility.
#
# IMPORTANT: Must be run directly on the VCF Ops appliance VM via SSH.
#
# Flow:
#   1. Acquire auth token from Ops
#   2. Resolve management VC GUID for the target vcfInstanceId
#   3. Find the existing external VIDB record by VIDB hostname
#   4. Fetch & decrypt the VIDB tenant client secret from local DB
#   5. PUT — update external VIDB with new vcGUID and vcfInstanceId
#      (vidbResourceId, certs, clientId, clientSecret remain unchanged)
#   6. Update collector for the external VIDB adapter
#      (find matching VC adapter by VMEntityVCID, update collectorId, verify)
#   7. Poll eligible VIDB API until the VIDB becomes eligible
#      (10s poll interval, 20-minute timeout)
#   8. [optional] Remove stale SSO domain config from kv_vidb_sso_domain
#      (if --sso-domain-id is given)
#
# Usage (run on ops node directly):
#   ./update-vidb-vcf-instance.sh \
#     --ops-host  vcfops1.vrack.vsphere.local \
#     --username  admin \
#     --password  'MyPassword' \
#     --vcf-id    a35ae4be-ab2f-490e-b1a4-5572f83f05d9 \
#     --vidb-host vmsp-vidb.vrack.vsphere.local \
#     [--sso-domain-id <key>]
#
# Prerequisites: curl, jq (auto-installed if missing), python3
# =============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "\n${BOLD}${BLUE}==> $*${NC}"; }

# =============================================================================
# Usage
# =============================================================================
usage() {
  cat <<EOF
${BOLD}Usage:${NC}
  $(basename "$0") [OPTIONS]

${BOLD}Description:${NC}
  DR recovery: updates the external VIDB record with the new VCF instance
  association (PUT), updates the adapter collector, waits for the VIDB to
  become eligible, then optionally removes the stale SSO domain config row.

  Run this script directly on the VCF Ops appliance VM via SSH.

${BOLD}Options:${NC}
  -H, --ops-host       OPS hostname (e.g., vcfops1.vrack.vsphere.local)          [required]
  -u, --username       Admin username                                             [required]
  -p, --password       Admin password                                             [required]
  -i, --vcf-id         New VCF Instance ID to associate                           [required]
  -v, --vidb-host      External VIDB FQDN (e.g., vmsp-vidb.vrack.vsphere.local)  [required]
  -d, --sso-domain-id  SSO domain key to remove from kv_vidb_sso_domain           [optional]
  -h, --help           Show this help

${BOLD}Examples:${NC}
  # Update VIDB only
  $(basename "$0") \\
    --ops-host  vcfops1.vrack.vsphere.local \\
    --username  admin --password 'pass' \\
    --vcf-id    a35ae4be-ab2f-490e-b1a4-5572f83f05d9 \\
    --vidb-host vmsp-vidb.vrack.vsphere.local

  # Update VIDB and remove SSO domain config
  $(basename "$0") \\
    --ops-host  vcfops1.vrack.vsphere.local \\
    --username  admin --password 'pass' \\
    --vcf-id    a35ae4be-ab2f-490e-b1a4-5572f83f05d9 \\
    --vidb-host vmsp-vidb.vrack.vsphere.local \\
    --sso-domain-id some-sso-domain-key
EOF
}

# =============================================================================
# Argument Parsing
# =============================================================================
OPS_HOST=""
USERNAME=""
PASSWORD=""
VCF_INSTANCE_ID=""
VIDB_FQDN=""
SSO_DOMAIN_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -H|--ops-host)      OPS_HOST="$2";         shift 2 ;;
    -u|--username)      USERNAME="$2";         shift 2 ;;
    -p|--password)      PASSWORD="$2";         shift 2 ;;
    -i|--vcf-id)        VCF_INSTANCE_ID="$2";  shift 2 ;;
    -v|--vidb-host)     VIDB_FQDN="$2";        shift 2 ;;
    -d|--sso-domain-id) SSO_DOMAIN_ID="$2";    shift 2 ;;
    -h|--help)          usage; exit 0 ;;
    *) log_error "Unknown option: $1"; echo; usage; exit 1 ;;
  esac
done

for var in OPS_HOST USERNAME PASSWORD VCF_INSTANCE_ID VIDB_FQDN; do
  [[ -n "${!var}" ]] || { log_error "Missing required argument: --${var//_/-}"; echo; usage; exit 1; }
done

TOTAL_STEPS=7
[[ -n "$SSO_DOMAIN_ID" ]] && TOTAL_STEPS=8

# Eligibility poll config
POLL_INTERVAL=10    # seconds between polls
POLL_TIMEOUT=1200   # total timeout: 20 minutes

# =============================================================================
# Dependency Check  (auto-installs jq if missing)
# =============================================================================
install_jq() {
  log_warn "jq not found — attempting auto-install..."

  if command -v tdnf &>/dev/null; then
    tdnf install -y jq &>/dev/null && command -v jq &>/dev/null && return 0
  fi
  if command -v apt-get &>/dev/null; then
    apt-get install -y jq &>/dev/null && command -v jq &>/dev/null && return 0
  fi
  if command -v yum &>/dev/null; then
    yum install -y jq &>/dev/null && command -v jq &>/dev/null && return 0
  fi

  local arch; arch=$(uname -m)
  local jq_arch="amd64"
  [[ "$arch" == "aarch64" || "$arch" == "arm64" ]] && jq_arch="arm64"

  log_info "Downloading jq-linux-${jq_arch} from GitHub releases..."
  if curl -sL \
       "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-${jq_arch}" \
       -o /usr/local/bin/jq && chmod +x /usr/local/bin/jq; then
    command -v jq &>/dev/null && return 0
  fi

  return 1
}

check_deps() {
  if ! command -v jq &>/dev/null; then
    install_jq || { log_error "Failed to install jq automatically. Install it manually and retry."; exit 1; }
    log_ok "jq installed: $(jq --version)"
  fi

  local missing=()
  for cmd in curl jq python3; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "Missing required tools: ${missing[*]}"
    exit 1
  fi
}

# =============================================================================
# API Helpers
# =============================================================================
ops_api() {
  local method="$1" path="$2"; shift 2
  curl -s -k -X "$method" \
    "https://${OPS_HOST}/suite-api/${path}" \
    -H "content-type: application/json" \
    "$@"
}

ops_internal() {
  local method="$1" path="$2"; shift 2
  curl -s -k -X "$method" \
    "https://${OPS_HOST}/suite-api/internal/${path}" \
    -H "authorization: vRealizeOpsToken ${TOKEN}" \
    -H "content-type: application/json" \
    -H "x-vrealizeops-api-use-unsupported: true" \
    "$@"
}

# Sets globals HTTP_CODE and HTTP_BODY
ops_internal_with_status() {
  local method="$1" path="$2"; shift 2
  local tmpfile; tmpfile=$(mktemp)
  HTTP_CODE=$(curl -s -k -o "$tmpfile" -w "%{http_code}" -X "$method" \
    "https://${OPS_HOST}/suite-api/internal/${path}" \
    -H "authorization: vRealizeOpsToken ${TOKEN}" \
    -H "content-type: application/json" \
    -H "x-vrealizeops-api-use-unsupported: true" \
    "$@")
  HTTP_BODY=$(cat "$tmpfile")
  rm -f "$tmpfile"
}

# Public API — /suite-api/api/ path with auth token (no unsupported header)
ops_public() {
  local method="$1" path="$2"; shift 2
  curl -s -k -X "$method" \
    "https://${OPS_HOST}/suite-api/${path}" \
    -H "authorization: vRealizeOpsToken ${TOKEN}" \
    -H "accept: application/json" \
    -H "content-type: application/json" \
    "$@"
}

# Sets globals HTTP_CODE and HTTP_BODY — public /suite-api/api/ path with auth token
ops_public_with_status() {
  local method="$1" path="$2"; shift 2
  local tmpfile; tmpfile=$(mktemp)
  HTTP_CODE=$(curl -s -k -o "$tmpfile" -w "%{http_code}" -X "$method" \
    "https://${OPS_HOST}/suite-api/${path}" \
    -H "authorization: vRealizeOpsToken ${TOKEN}" \
    -H "accept: application/json" \
    -H "content-type: application/json" \
    "$@")
  HTTP_BODY=$(cat "$tmpfile")
  rm -f "$tmpfile"
}

# =============================================================================
# Certificate Normalizer
#
# The GET /vidb/vmsp/vidbs response returns PEM certs with spaces between
# base64 lines instead of newlines.  This function:
#   1. Locates each PEM block  (-----BEGIN TYPE----- ... -----END TYPE-----)
#   2. Strips ALL whitespace (spaces, real newlines, literal \n, tabs) from
#      the base64 body
#   3. Re-wraps the base64 at 64 chars per line with real \n separators
#
# Result is a properly-formatted PEM that the server stores with \n.
# =============================================================================
normalize_cert() {
  local cert="$1"
  printf '%s' "$cert" | python3 -c "
import sys, re, textwrap

cert = sys.stdin.read().strip()
if not cert:
    sys.exit(0)

def reformat_block(m):
    cert_type = m.group(1)
    raw = m.group(2)
    # Strip every kind of whitespace so we get pure base64
    b64 = re.sub(r'\s+', '', raw)
    # Wrap at 64 chars per line
    lines = textwrap.wrap(b64, 64)
    return '-----BEGIN {}-----\n{}\n-----END {}-----'.format(
        cert_type, '\n'.join(lines), cert_type)

result = re.sub(
    r'-----BEGIN ([^-]+)-----(.*?)-----END \1-----',
    reformat_block,
    cert,
    flags=re.DOTALL
)
print(result)
"
}

# =============================================================================
# Step 4 Helper — Python: query credential DB, read key, decrypt CLIENT_SECRET
#
# Input:  VIDB_FQDN_ENV environment variable
# Output: plaintext CLIENT_SECRET printed to stdout
# =============================================================================
write_step4_python() {
  local dest="$1"
  cat > "$dest" << 'PYEOF'
import subprocess, json, base64, tempfile, os, sys

vidb_fqdn = os.environ.get('VIDB_FQDN_ENV', '').strip()
if not vidb_fqdn:
    print("ERROR: VIDB_FQDN_ENV not set", file=sys.stderr)
    sys.exit(1)

sql = (
    "SELECT fields FROM credential "
    "WHERE adapter_key='VMWARE_INFRA_MANAGEMENT' "
    f"AND credential_name='{vidb_fqdn}';"
)
with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False, dir='/tmp') as f:
    f.write(sql + '\n')
    sql_file = f.name

os.chmod(sql_file, 0o644)

try:
    result = subprocess.run(
        ['su', '-', 'postgres', '-c',
         f'/opt/vmware/vpostgres/current/bin/psql -p 5433 -d vcopsdb -t -A -f {sql_file}'],
        capture_output=True, text=True
    )
    fields_raw = result.stdout.strip()
finally:
    os.unlink(sql_file)

if not fields_raw:
    print(
        f"ERROR: No credential found for "
        f"adapter_key=VMWARE_INFRA_MANAGEMENT / credential_name={vidb_fqdn}",
        file=sys.stderr
    )
    sys.exit(1)

try:
    fields = json.loads(fields_raw)
except json.JSONDecodeError as e:
    print(f"ERROR: Failed to parse credential fields JSON: {e}", file=sys.stderr)
    sys.exit(1)

encrypted_secret = None
for field in fields:
    if field.get('credentialFieldKey') == 'CLIENT_SECRET':
        encrypted_secret = field['value']
        break

if not encrypted_secret:
    print("ERROR: CLIENT_SECRET field not found in credential fields", file=sys.stderr)
    sys.exit(1)

parts = encrypted_secret.split(':', 2)
if len(parts) != 3:
    print(f"ERROR: Unexpected encrypted secret format ({len(parts)} parts)", file=sys.stderr)
    sys.exit(1)

version, iv_b64, data_b64 = parts

master_key = None
key_file = '/usr/lib/vmware-vcops/user/conf/cluster_master_key.txt'
try:
    with open(key_file) as kf:
        for line in kf:
            line = line.strip()
            prefix = f'{version} KEY='
            if line.startswith(prefix):
                master_key = line[len(prefix):]
                break
except FileNotFoundError:
    print(f"ERROR: {key_file} not found", file=sys.stderr)
    sys.exit(1)

if not master_key:
    print(f"ERROR: No key found for version '{version}' in {key_file}", file=sys.stderr)
    sys.exit(1)

key_hex    = base64.b64decode(master_key).hex()
iv_hex     = base64.b64decode(iv_b64).hex()
data_bytes = base64.b64decode(data_b64)

proc = subprocess.run(
    ['openssl', 'enc', '-aes-128-cbc', '-d', '-K', key_hex, '-iv', iv_hex],
    input=data_bytes, capture_output=True
)

if proc.returncode != 0:
    print(f"ERROR: openssl decryption failed: {proc.stderr.decode().strip()}", file=sys.stderr)
    sys.exit(1)

print(proc.stdout.decode('utf-8').strip())
PYEOF
}

# =============================================================================
# Step 6 Helper — Python: find and delete SSO domain row from kv_vidb_sso_domain
#
# Input:  SSO_DOMAIN_ID_ENV environment variable
# Output: prints "DELETED" on success, exits non-zero on failure
# =============================================================================
write_step6_python() {
  local dest="$1"
  cat > "$dest" << 'PYEOF'
import re, subprocess, tempfile, os, sys

sso_domain_id = os.environ.get('SSO_DOMAIN_ID_ENV', '').strip()
if not sso_domain_id:
    print("ERROR: SSO_DOMAIN_ID_ENV not set", file=sys.stderr)
    sys.exit(1)

# Validate UUID format to guard against SQL injection
if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                sso_domain_id, re.IGNORECASE):
    print(f"ERROR: SSO_DOMAIN_ID_ENV is not a valid UUID: '{sso_domain_id}'", file=sys.stderr)
    sys.exit(1)

PSQL = '/opt/vmware/vpostgres/current/bin/psql -p 5433 -d vcopsdb -t -A'

def run_sql(sql):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False, dir='/tmp') as f:
        f.write(sql + '\n')
        sql_file = f.name
    os.chmod(sql_file, 0o644)
    try:
        result = subprocess.run(
            ['su', '-', 'postgres', '-c', f'{PSQL} -f {sql_file}'],
            capture_output=True, text=True
        )
    finally:
        os.unlink(sql_file)
    return result

# ---- (a) Targeted fetch: SELECT key WHERE key = '<id>' ----
result = run_sql(f"SELECT key FROM kv_vidb_sso_domain WHERE key = '{sso_domain_id}';")
if result.returncode != 0:
    print(f"ERROR: SELECT failed: {result.stderr.strip()}", file=sys.stderr)
    sys.exit(1)

found = result.stdout.strip()
if not found:
    print(
        f"ERROR: No record found in kv_vidb_sso_domain with key='{sso_domain_id}'",
        file=sys.stderr
    )
    sys.exit(1)

# ---- (b) Delete the row ----
result = run_sql(f"DELETE FROM kv_vidb_sso_domain WHERE key = '{sso_domain_id}';")
if result.returncode != 0:
    print(f"ERROR: DELETE failed: {result.stderr.strip()}", file=sys.stderr)
    sys.exit(1)

# ---- (c) Verify deletion: row count must be 0 ----
result = run_sql(f"SELECT COUNT(*) FROM kv_vidb_sso_domain WHERE key = '{sso_domain_id}';")
if result.returncode != 0:
    print(f"ERROR: Post-delete verification failed: {result.stderr.strip()}", file=sys.stderr)
    sys.exit(1)

count = result.stdout.strip()
if count != '0':
    print(f"ERROR: Row still present after DELETE (count={count})", file=sys.stderr)
    sys.exit(1)

print("DELETED")
PYEOF
}

# =============================================================================
# DB Step Runner
# Runs a Python script locally with the given KEY=VALUE environment variable.
# Sets STEP_OUTPUT global.
# =============================================================================
run_db_python() {
  local py_script="$1"
  local env_kv="$2"        # KEY=VALUE with no shell quoting inside (e.g. FOO=bar.baz)
  local stderr_file; stderr_file=$(mktemp)
  local output=""

  if ! output=$(env "$env_kv" python3 "$py_script" 2>"$stderr_file"); then
    log_error "python3 execution failed."
    [[ -s "$stderr_file" ]] && log_error "$(cat "$stderr_file")"
    rm -f "$stderr_file"
    return 1
  fi

  rm -f "$stderr_file"
  STEP_OUTPUT="$output"
}

# =============================================================================
# Main
# =============================================================================
main() {
  check_deps

  echo -e "\n${BOLD}╔════════════════════════════════════════════════════╗${NC}"
  echo -e   "${BOLD}║        VIDB VCF Instance Updater                   ║${NC}"
  echo -e   "${BOLD}╚════════════════════════════════════════════════════╝${NC}"
  log_info "OPS Host       : ${OPS_HOST}"
  log_info "VCF Instance   : ${VCF_INSTANCE_ID}"
  log_info "VIDB Host      : ${VIDB_FQDN}"
  [[ -n "$SSO_DOMAIN_ID" ]] && log_info "SSO Domain ID  : ${SSO_DOMAIN_ID}"

  # --------------------------------------------------------------------------
  # Step 1: Acquire Auth Token
  # --------------------------------------------------------------------------
  log_step "Step 1/${TOTAL_STEPS}  Acquiring auth token"

  TOKEN_RESP=$(ops_api POST "api/auth/token/acquire" \
    -d "{\"username\": \"${USERNAME}\", \"password\": \"${PASSWORD}\"}")

  TOKEN=$(echo "$TOKEN_RESP" | jq -r '.token // empty')
  if [[ -z "$TOKEN" ]]; then
    log_error "Failed to acquire token."
    log_error "Response: $(echo "$TOKEN_RESP" | jq -r '.message // .' 2>/dev/null || echo "$TOKEN_RESP")"
    exit 1
  fi
  log_ok "Token acquired"

  # --------------------------------------------------------------------------
  # Step 2: Resolve Management VC GUID
  #   GET /internal/vidb/vidbs
  #   Filter: vcfInstanceId == INPUT and deploymentType == "EMBEDDED"
  # --------------------------------------------------------------------------
  log_step "Step 2/${TOTAL_STEPS}  Resolving management VC GUID for vcfInstanceId"

  ELIGIBLE_VIDBS=$(ops_internal GET "vidb/vidbs")

  MGMT_VC_GUID=$(echo "$ELIGIBLE_VIDBS" | jq -r \
    --arg vcfId "$VCF_INSTANCE_ID" \
    '.[] | select(.vcfInstanceId == $vcfId and .deploymentType == "EMBEDDED") | .id // empty')

  if [[ -z "$MGMT_VC_GUID" ]]; then
    log_error "No VCF instance found for vcfInstanceId: ${VCF_INSTANCE_ID}"
    log_warn "Registered VCF instances:"
    echo "$ELIGIBLE_VIDBS" | jq -r \
      '.[] | "  [\(.deploymentType)] \(.fqdn)  vcfInstanceId=\(.vcfInstanceId)"' 2>/dev/null \
      || echo "$ELIGIBLE_VIDBS"
    exit 1
  fi
  log_ok "Management VC GUID: ${MGMT_VC_GUID}"

  # --------------------------------------------------------------------------
  # Step 3: Find External VIDB Record
  #   GET /internal/vidb/vmsp/vidbs
  #   Filter: externalVidbs[].vidbHost == VIDB_FQDN
  # --------------------------------------------------------------------------
  log_step "Step 3/${TOTAL_STEPS}  Finding external VIDB record for '${VIDB_FQDN}'"

  EXT_VIDBS_RESP=$(ops_internal GET "vidb/vmsp/vidbs")

  EXT_VIDB=$(echo "$EXT_VIDBS_RESP" | jq \
    --arg host "$VIDB_FQDN" '.externalVidbs[] | select(.vidbHost == $host)')

  if [[ -z "$EXT_VIDB" || "$EXT_VIDB" == "null" ]]; then
    log_error "No external VIDB found with vidbHost: ${VIDB_FQDN}"
    log_warn "Available external VIDBs:"
    echo "$EXT_VIDBS_RESP" | jq -r \
      '.externalVidbs[] | "  \(.vidbHost)  (id: \(.id))"' 2>/dev/null \
      || echo "$EXT_VIDBS_RESP"
    exit 1
  fi

  EXT_VIDB_ID=$(echo "$EXT_VIDB"       | jq -r '.id')
  VIDB_RESOURCE_ID=$(echo "$EXT_VIDB"  | jq -r '.vidbResourceId')
  CLIENT_ID=$(echo "$EXT_VIDB"         | jq -r '.clientId')
  TRUSTED_ROOT_CERT=$(echo "$EXT_VIDB" | jq -r '.trustedRootCertPem')
  TLS_CERT=$(echo "$EXT_VIDB"          | jq -r '.tlsCertPem')

  # Normalise cert newlines: literal \n or tabs → actual newline characters
  TRUSTED_ROOT_CERT=$(normalize_cert "$TRUSTED_ROOT_CERT")
  TLS_CERT=$(normalize_cert "$TLS_CERT")

  CERT_NL_STATUS="WARN (no newlines detected — cert may be single-line)"
  printf '%s' "$TRUSTED_ROOT_CERT" | grep -q $'\n' && CERT_NL_STATUS="OK (actual newlines present)"

  log_ok "External VIDB ID  : ${EXT_VIDB_ID}"
  log_info "  vidbResourceId : ${VIDB_RESOURCE_ID}"
  log_info "  clientId       : ${CLIENT_ID}"
  log_info "  cert newlines  : ${CERT_NL_STATUS}"

  # --------------------------------------------------------------------------
  # Step 4: Fetch & Decrypt CLIENT_SECRET
  # --------------------------------------------------------------------------
  log_step "Step 4/${TOTAL_STEPS}  Fetching & decrypting CLIENT_SECRET from local DB"

  PY4=$(mktemp /tmp/vidb_step4_XXXX.py)
  # shellcheck disable=SC2064
  trap "rm -f '$PY4'" EXIT
  write_step4_python "$PY4"

  STEP_OUTPUT=""
  run_db_python "$PY4" "VIDB_FQDN_ENV=${VIDB_FQDN}" || exit 1
  CLIENT_SECRET="$STEP_OUTPUT"

  rm -f "$PY4"
  trap - EXIT

  if [[ -z "$CLIENT_SECRET" ]]; then
    log_error "CLIENT_SECRET is empty after decryption."
    exit 1
  fi
  log_ok "CLIENT_SECRET retrieved"

  # --------------------------------------------------------------------------
  # Step 5: PUT — Update External VIDB Association
  #   Same vidbResourceId, vidbHost, clientId, clientSecret, certs
  #   Updated vcGUID and vcfInstanceId
  # --------------------------------------------------------------------------
  log_step "Step 5/${TOTAL_STEPS}  Updating external VIDB (PUT)"

  PUT_PAYLOAD=$(jq -n \
    --arg id                 "$EXT_VIDB_ID" \
    --arg vidbResourceId     "$VIDB_RESOURCE_ID" \
    --arg vidbHost           "$VIDB_FQDN" \
    --arg vcGUID             "$MGMT_VC_GUID" \
    --arg vcfInstanceId      "$VCF_INSTANCE_ID" \
    --arg clientId           "$CLIENT_ID" \
    --arg clientSecret       "$CLIENT_SECRET" \
    --arg trustedRootCertPem "$TRUSTED_ROOT_CERT" \
    --arg tlsCertPem         "$TLS_CERT" \
    '{
      id:                 $id,
      vidbResourceId:     $vidbResourceId,
      vidbHost:           $vidbHost,
      vcGUID:             $vcGUID,
      vcfInstanceId:      $vcfInstanceId,
      clientId:           $clientId,
      clientSecret:       $clientSecret,
      trustedRootCertPem: $trustedRootCertPem,
      tlsCertPem:         $tlsCertPem
    }')

  HTTP_CODE="" HTTP_BODY=""
  ops_internal_with_status PUT "vidb/vmsp/${EXT_VIDB_ID}" -d "$PUT_PAYLOAD"

  if [[ "$HTTP_CODE" =~ ^2 ]]; then
    log_ok "External VIDB updated (HTTP ${HTTP_CODE})"
    log_info "  External VIDB ID : ${EXT_VIDB_ID}"
    log_info "  VIDB Host        : ${VIDB_FQDN}"
    log_info "  VIDB Resource ID : ${VIDB_RESOURCE_ID}"
    log_info "  New VCF Instance : ${VCF_INSTANCE_ID}"
    log_info "  New VC GUID      : ${MGMT_VC_GUID}"
  else
    log_error "PUT failed (HTTP ${HTTP_CODE})"
    log_error "Response: $(echo "$HTTP_BODY" | jq -r '.message // .' 2>/dev/null || echo "$HTTP_BODY")"
    exit 1
  fi

  # --------------------------------------------------------------------------
  # Step 6: Update Collector for External VIDB Adapter
  #   6a. GET /api/adapters?adapterKindKey=VMWARE — find collectorId for management VC
  #       Match: resourceIdentifiers[].identifierType.name == "VMEntityVCID"
  #              and value == MGMT_VC_GUID
  #   6b. GET /api/adapters/<EXT_VIDB_ID> — fetch current VIDB adapter details
  #   6c. PUT /api/adapters — update VIDB adapter with new collectorId
  #   6d. GET /api/adapters/<EXT_VIDB_ID> — verify collectorId is updated
  # --------------------------------------------------------------------------
  log_step "Step 6/${TOTAL_STEPS}  Updating collector for external VIDB adapter"

  log_info "  [6a] Fetching VMWARE adapter list to resolve collector for VC GUID: ${MGMT_VC_GUID}"
  VC_ADAPTERS=$(ops_public GET "api/adapters?adapterKindKey=VMWARE&_no_links=true")

  TARGET_COLLECTOR_ID=$(echo "$VC_ADAPTERS" | jq -r \
    --arg vcguid "$MGMT_VC_GUID" \
    '(.adapterInstancesInfoDto // [])[] |
     select((.resourceKey.resourceIdentifiers // [])[] |
       .identifierType.name == "VMEntityVCID" and .value == $vcguid) |
     .collectorId // empty')

  if [[ -z "$TARGET_COLLECTOR_ID" ]]; then
    log_error "No VMWARE adapter found with VMEntityVCID = ${MGMT_VC_GUID}"
    log_warn "Available VMWARE adapters:"
    echo "$VC_ADAPTERS" | jq -r \
      '(.adapterInstancesInfoDto // [])[] | "  \(.resourceKey.name)  collectorId=\(.collectorId)"' \
      2>/dev/null || echo "$VC_ADAPTERS"
    exit 1
  fi
  log_ok "Target collector ID resolved: ${TARGET_COLLECTOR_ID}"

  log_info "  [6b] Fetching external VIDB adapter details (id: ${EXT_VIDB_ID})"
  VIDB_ADAPTER=$(ops_public GET "api/adapters/${EXT_VIDB_ID}?_no_links=true")

  CURRENT_COLLECTOR_ID=$(echo "$VIDB_ADAPTER" | jq -r '.collectorId // empty')
  if [[ -z "$CURRENT_COLLECTOR_ID" ]]; then
    log_error "Failed to fetch VIDB adapter details for id: ${EXT_VIDB_ID}"
    log_error "Response: $(echo "$VIDB_ADAPTER" | jq -r '.message // .' 2>/dev/null || echo "$VIDB_ADAPTER")"
    exit 1
  fi
  log_info "  Current collector ID : ${CURRENT_COLLECTOR_ID}"
  log_info "  Target  collector ID : ${TARGET_COLLECTOR_ID}"

  if [[ "$CURRENT_COLLECTOR_ID" == "$TARGET_COLLECTOR_ID" ]]; then
    log_ok "Collector is already set to ${TARGET_COLLECTOR_ID} — no update needed"
  else
    log_info "  [6c] Updating VIDB adapter collectorId to ${TARGET_COLLECTOR_ID}"
    UPDATED_VIDB_ADAPTER=$(echo "$VIDB_ADAPTER" | jq \
      --argjson cid "$TARGET_COLLECTOR_ID" '.collectorId = $cid')

    HTTP_CODE="" HTTP_BODY=""
    ops_public_with_status PUT "api/adapters?_no_links=true" -d "$UPDATED_VIDB_ADAPTER"

    if [[ "$HTTP_CODE" =~ ^2 ]]; then
      log_ok "Collector PUT accepted (HTTP ${HTTP_CODE})"
    else
      log_error "Collector PUT failed (HTTP ${HTTP_CODE})"
      log_error "Response: $(echo "$HTTP_BODY" | jq -r '.message // .' 2>/dev/null || echo "$HTTP_BODY")"
      exit 1
    fi

    log_info "  [6d] Verifying collector update"
    VERIFY_ADAPTER=$(ops_public GET "api/adapters/${EXT_VIDB_ID}?_no_links=true")
    VERIFIED_COLLECTOR_ID=$(echo "$VERIFY_ADAPTER" | jq -r '.collectorId // empty')

    if [[ "$VERIFIED_COLLECTOR_ID" == "$TARGET_COLLECTOR_ID" ]]; then
      log_ok "Collector verified: collectorId=${VERIFIED_COLLECTOR_ID}"
    else
      log_error "Collector verification failed: expected ${TARGET_COLLECTOR_ID}, got ${VERIFIED_COLLECTOR_ID:-<empty>}"
      exit 1
    fi
  fi

  # --------------------------------------------------------------------------
  # Step 7: Poll eligible VIDB API until the VIDB is eligible
  #   GET /internal/vidb/vidbs
  #   Match:  .id == VIDB_RESOURCE_ID  (the vidbResourceId is the stable identity)
  #   Condition: .vidbStatus.eligibilityStatus == "ELIGIBLE"
  #   Poll every POLL_INTERVAL seconds; fail after POLL_TIMEOUT seconds (20 min).
  # --------------------------------------------------------------------------
  log_step "Step 7/${TOTAL_STEPS}  Waiting for VIDB to become eligible (timeout: ${POLL_TIMEOUT}s)"
  log_info "  Polling every ${POLL_INTERVAL}s for vidbResourceId=${VIDB_RESOURCE_ID}"

  elapsed=0
  ELIGIBILITY_STATUS=""
  while [[ $elapsed -lt $POLL_TIMEOUT ]]; do
    ELIGIBLE_LIST=$(ops_internal GET "vidb/vidbs" 2>/dev/null || true)

    ELIGIBILITY_STATUS=$(echo "$ELIGIBLE_LIST" | jq -r \
      --arg rid "$VIDB_RESOURCE_ID" \
      '.[] | select(.id == $rid) | .vidbStatus.eligibilityStatus // empty' \
      2>/dev/null || true)

    if [[ "$ELIGIBILITY_STATUS" == "ELIGIBLE" ]]; then
      log_ok "VIDB is ELIGIBLE (elapsed: ${elapsed}s)"
      log_info "  VIDB Resource ID : ${VIDB_RESOURCE_ID}"
      break
    fi

    if [[ -n "$ELIGIBILITY_STATUS" ]]; then
      log_info "  Status: ${ELIGIBILITY_STATUS} — ${elapsed}s elapsed, retrying in ${POLL_INTERVAL}s..."
    else
      log_info "  Not yet visible in eligible list — ${elapsed}s elapsed, retrying in ${POLL_INTERVAL}s..."
    fi
    sleep "$POLL_INTERVAL"
    elapsed=$((elapsed + POLL_INTERVAL))
  done

  if [[ "$ELIGIBILITY_STATUS" != "ELIGIBLE" ]]; then
    log_error "Timed out after ${POLL_TIMEOUT}s — last status: ${ELIGIBILITY_STATUS:-<not found>}"
    log_warn "The VIDB record was updated. Verify connectivity between Ops and the VIDB manually."
    exit 1
  fi

  # --------------------------------------------------------------------------
  # Step 8: Remove SSO Domain Config from DB  [only if --sso-domain-id given]
  # --------------------------------------------------------------------------
  if [[ -z "$SSO_DOMAIN_ID" ]]; then
    log_info "No --sso-domain-id provided — skipping SSO domain removal."
    echo ""
    log_ok "All ${TOTAL_STEPS} steps completed successfully"
    return 0
  fi

  log_step "Step 8/${TOTAL_STEPS}  Removing SSO domain config from kv_vidb_sso_domain"
  log_info "  SSO Domain ID : ${SSO_DOMAIN_ID}"

  PY6=$(mktemp /tmp/vidb_step8_XXXX.py)
  # shellcheck disable=SC2064
  trap "rm -f '$PY6'" EXIT
  write_step6_python "$PY6"

  STEP_OUTPUT=""
  run_db_python "$PY6" "SSO_DOMAIN_ID_ENV=${SSO_DOMAIN_ID}" || exit 1

  rm -f "$PY6"
  trap - EXIT

  if [[ "$STEP_OUTPUT" == "DELETED" ]]; then
    log_ok "SSO domain config removed from kv_vidb_sso_domain"
  else
    log_error "Unexpected output from SSO domain deletion: ${STEP_OUTPUT}"
    exit 1
  fi

  echo ""
  log_ok "All ${TOTAL_STEPS} steps completed successfully"
}

main "$@"

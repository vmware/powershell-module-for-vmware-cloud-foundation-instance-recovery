#!/bin/bash
# =============================================================================
# migrate-vidb-vcf-instance.sh
#
# Unified DR script for re-associating an external VIDB with a new VCF
# instance in VCF Operations. Auto-selects the correct migration flow via a
# feature flag (VIDB_MIGRATION_FLOW) based on the running VCF Operations
# version:
#
#   - version == 9.1.0             -> "db"  flow  (same logic as
#                                      update-vidb-vcf-instance.sh: PUT via
#                                      internal API + local DB secret
#                                      decrypt + optional SSO domain cleanup)
#   - version  > 9.1.0 (9.1.1, 9.1.2, 9.1.3, 9.2.0, ...)
#                                   -> "api" flow  (same logic as
#                                      move-vidb-api.sh: PATCH via API only,
#                                      no DB access, plus SSO Realm update)
#
# The version is read from:
#   GET /suite-api/api/versions/current?_no_links=true
# using major.minor.minorMinor (e.g. 9.2.0.0 -> "9.2.0").
#
# The flow can be forced with --flow db|api, bypassing version detection
# (useful for testing).
#
# Each flow's step-by-step behavior is unchanged from its source script.
# Only genuinely identical logic (auth token acquisition, resolving the
# management VC GUID for a vcfInstanceId, fetching the external VIDB record)
# has been factored into shared helper functions.
#
# Usage:
#   There is no --password flag — the OPS password is always prompted for
#   securely (silent read, no echo), same as OPS_PASSWORD in
#   restore_and_update_vidb.sh.
#
#   --username defaults to "admin" and is optional — pass --username to
#   override it.
#
#   --target-vcf and --sso-realm are shared by both flows (same IDs either
#   way): the db flow uses --target-vcf to resolve the management VC and
#   --sso-realm (optional) to remove the stale kv_vidb_sso_domain row; the
#   api flow uses --target-vcf to PATCH the VIDB association and
#   --sso-realm to PATCH the SSO Realm's VCF instance.
#
#   DB flow (version 9.1.0 — run directly on the ops appliance via SSH):
#     ./migrate-vidb-vcf-instance.sh \
#       --ops-host   vcfops1.vrack.vsphere.local \
#       --target-vcf a35ae4be-ab2f-490e-b1a4-5572f83f05d9 \
#       --vidb-host  vmsp-vidb.vrack.vsphere.local \
#       [--username <user>] [--sso-realm <SSO Realm ID>]
#
#   API flow (version > 9.1.0 — can be run from anywhere with network access):
#     ./migrate-vidb-vcf-instance.sh \
#       --ops-fqdn   vcfops1.vrack.vsphere.local \
#       --vidb-host  vmsp-vidb.vrack.vsphere.local \
#       --target-vcf b47ce5df-bc3g-491f-c2b5-6683g94g16e0 \
#       --sso-realm  4959d760-c09a-4ff3-aeac-d38e0f7209d9
#
#   Force a flow (skips the version lookup):
#     ./migrate-vidb-vcf-instance.sh ... --flow db
#     ./migrate-vidb-vcf-instance.sh ... --flow api
#
# Prerequisites: curl, jq (auto-installed if missing); python3 (db flow only)
# =============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# All log output goes to stderr — several functions (get_vidb_version,
# resolve_mgmt_vc_guid, fetch_ext_vidb_record, determine_flow, acquire_token)
# are invoked via command substitution and use stdout as their return
# channel; a log line on stdout would silently corrupt the captured value.
log_info()    { echo -e "${BLUE}[INFO]${NC}  $*" >&2; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*" >&2; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "\n${BOLD}${BLUE}==> $*${NC}" >&2; }

# =============================================================================
# Usage
# =============================================================================
usage() {
  cat <<EOF
${BOLD}Usage:${NC}
  $(basename "$0") [OPTIONS]

${BOLD}Description:${NC}
  DR recovery: re-associates the external VIDB record with a new VCF
  instance. The migration flow (db vs api) is auto-selected from the
  VCF Operations version (feature flag), or forced with --flow.

${BOLD}Common Options:${NC}
  -H, --ops-host       OPS hostname                                            [required]
  -f, --ops-fqdn       Alias of --ops-host                                     [required]
  -u, --username       Admin username (default: admin)                        [optional]
  -v, --vidb-host      External VIDB FQDN                                     [required]
  -t, --target-vcf     VCF Instance ID to associate — same value used by both flows [required]
  -s, --sso-realm      SSO Realm ID (UUID) — same value used by both flows    [optional for db flow, required for api flow]
      --flow           Force flow: 'db' or 'api' (skips version detection)    [optional]
  -h, --help           Show this help

  OPS password is not a flag — you will be prompted for it securely.

${BOLD}Examples:${NC}
  # Auto-detected db flow (username defaults to "admin")
  $(basename "$0") \\
    --ops-host   vcfops1.vrack.vsphere.local \\
    --target-vcf a35ae4be-ab2f-490e-b1a4-5572f83f05d9 \\
    --vidb-host  vmsp-vidb.vrack.vsphere.local

  # Auto-detected api flow
  $(basename "$0") \\
    --ops-fqdn   vcfops1.vrack.vsphere.local \\
    --vidb-host  vmsp-vidb.vrack.vsphere.local \\
    --target-vcf b47ce5df-bc3g-491f-c2b5-6683g94g16e0 \\
    --sso-realm  4959d760-c09a-4ff3-aeac-d38e0f7209d9

  # Force the flow explicitly
  $(basename "$0") ... --flow api
EOF
}

# =============================================================================
# Argument Parsing
# =============================================================================
OPS_HOST=""
USERNAME="admin"
PASSWORD=""
VIDB_FQDN=""
TARGET_VCF_ID=""
SSO_REALM_ID=""
FLOW_OVERRIDE=""

# Parses CLI args and validates the common required ones. Kept in a function
# (rather than top-level code) so this file can be sourced — e.g. by tests —
# without parsing/validation running as a side effect of sourcing.
# There is no --password flag; see prompt_for_password().
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -H|--ops-host)      OPS_HOST="$2";         shift 2 ;;
      -f|--ops-fqdn)      OPS_HOST="$2";         shift 2 ;;
      -u|--username)      USERNAME="$2";         shift 2 ;;
      -v|--vidb-host)     VIDB_FQDN="$2";        shift 2 ;;
      -t|--target-vcf)    TARGET_VCF_ID="$2";    shift 2 ;;
      -s|--sso-realm)     SSO_REALM_ID="$2";     shift 2 ;;
      --flow)             FLOW_OVERRIDE="$2";    shift 2 ;;
      -h|--help)          usage; exit 0 ;;
      *) log_error "Unknown option: $1"; echo; usage; exit 1 ;;
    esac
  done

  for var in OPS_HOST VIDB_FQDN TARGET_VCF_ID; do
    [[ -n "${!var}" ]] || { log_error "Missing required argument: --${var//_/-}"; echo; usage; exit 1; }
  done
}

# There is no --password flag. Always prompt, the same way
# restore_and_update_vidb.sh prompts for OPS_PASSWORD — silent read, no
# plaintext echo, no shell-history/process-list exposure.
prompt_for_password() {
  read -rsp "Enter OPS Password: " PASSWORD
  echo ""

  [[ -n "$PASSWORD" ]] || { log_error "OPS password is required"; exit 1; }
}

# Eligibility poll config (shared by both flows)
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
  for cmd in curl jq; do
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
# Feature Flag — Version Detection
#
# GET /suite-api/api/versions/current?_no_links=true. Some deployments gate
# this behind auth (returns an HTML "Not Authorized" page instead of JSON
# without a token), so a token is acquired first if we don't already have one.
# Version format used for comparison: major.minor.minorMinor (e.g. "9.2.0").
# =============================================================================
get_vidb_version() {
  local resp major minor minor_minor

  [[ -n "${TOKEN:-}" ]] || acquire_token

  resp=$(curl -s -k -X GET \
    "https://${OPS_HOST}/suite-api/api/versions/current?_no_links=true" \
    -H "accept: application/json" \
    -H "authorization: vRealizeOpsToken ${TOKEN}")

  major=$(echo "$resp" | jq -r '.major // empty' 2>/dev/null)
  minor=$(echo "$resp" | jq -r '.minor // empty' 2>/dev/null)
  minor_minor=$(echo "$resp" | jq -r '.minorMinor // empty' 2>/dev/null)

  if [[ -z "$major" || -z "$minor" || -z "$minor_minor" ]]; then
    log_error "Failed to determine VCF Operations version from ${OPS_HOST}"
    log_error "Response: ${resp}"
    exit 1
  fi

  echo "${major}.${minor}.${minor_minor}"
}

# Returns success (0) if version $1 is strictly greater than version $2.
# Both are dotted major.minor.patch strings.
version_gt() {
  [[ "$1" == "$2" ]] && return 1

  local IFS=.
  # shellcheck disable=SC2206
  local v1=($1) v2=($2)
  local i n1 n2
  for ((i = 0; i < 3; i++)); do
    n1="${v1[i]:-0}"
    n2="${v2[i]:-0}"
    if ((10#$n1 > 10#$n2)); then return 0; fi
    if ((10#$n1 < 10#$n2)); then return 1; fi
  done
  return 1
}

# Resolves which flow to run. Honors --flow override; otherwise auto-detects
# from the running VCF Operations version.
determine_flow() {
  if [[ -n "$FLOW_OVERRIDE" ]]; then
    case "$FLOW_OVERRIDE" in
      db|api) echo "$FLOW_OVERRIDE"; return 0 ;;
      *) log_error "Invalid --flow value: '${FLOW_OVERRIDE}' (expected 'db' or 'api')"; exit 1 ;;
    esac
  fi

  local ver
  ver=$(get_vidb_version)
  log_info "Detected VCF Operations version: ${ver}"

  if [[ "$ver" == "9.1.0" ]]; then
    echo "db"
  elif version_gt "$ver" "9.1.0"; then
    echo "api"
  else
    log_error "Unsupported VCF Operations version: ${ver} (this script supports 9.1.0 and above)"
    exit 1
  fi
}

# =============================================================================
# Shared Steps (identical logic across both flows)
# =============================================================================

# Step: Acquire Auth Token
acquire_token() {
  local resp
  resp=$(ops_api POST "api/auth/token/acquire" \
    -d "{\"username\": \"${USERNAME}\", \"password\": \"${PASSWORD}\"}")

  TOKEN=$(echo "$resp" | jq -r '.token // empty')
  if [[ -z "$TOKEN" ]]; then
    log_error "Failed to acquire token."
    log_error "Response: $(echo "$resp" | jq -r '.message // .' 2>/dev/null || echo "$resp")"
    exit 1
  fi
  log_ok "Token acquired"
}

# Step: Resolve management VC GUID for a given vcfInstanceId
#   GET /internal/vidb/vidbs
#   Filter: vcfInstanceId == $1 and deploymentType == "EMBEDDED"
# Prints the resolved GUID on stdout.
resolve_mgmt_vc_guid() {
  local target_vcf_id="$1"
  local vidbs_list mgmt_guid

  vidbs_list=$(ops_internal GET "vidb/vidbs")

  mgmt_guid=$(echo "$vidbs_list" | jq -r \
    --arg vcfId "$target_vcf_id" \
    '.[] | select(.vcfInstanceId == $vcfId and .deploymentType == "EMBEDDED") | .id // empty')

  if [[ -z "$mgmt_guid" ]]; then
    log_error "No VCF instance found for vcfInstanceId: ${target_vcf_id}"
    log_warn "Registered VCF instances:"
    echo "$vidbs_list" | jq -r \
      '.[] | "  [\(.deploymentType)] \(.fqdn)  vcfInstanceId=\(.vcfInstanceId)"' 2>/dev/null \
      || echo "$vidbs_list"
    exit 1
  fi

  echo "$mgmt_guid"
}

# Step: Fetch the external VIDB record by VIDB hostname
#   GET /internal/vidb/vmsp/vidbs
#   Filter: externalVidbs[].vidbHost == $1
# Prints the matching VIDB JSON object on stdout.
fetch_ext_vidb_record() {
  local vidb_host="$1"
  local resp ext_vidb

  resp=$(ops_internal GET "vidb/vmsp/vidbs")

  ext_vidb=$(echo "$resp" | jq --arg host "$vidb_host" '.externalVidbs[] | select(.vidbHost == $host)')

  if [[ -z "$ext_vidb" || "$ext_vidb" == "null" ]]; then
    log_error "No external VIDB found with vidbHost: ${vidb_host}"
    log_warn "Available external VIDBs:"
    echo "$resp" | jq -r \
      '.externalVidbs[] | "  \(.vidbHost)  (id: \(.id))"' 2>/dev/null \
      || echo "$resp"
    exit 1
  fi

  echo "$ext_vidb"
}

# =============================================================================
# "db" flow helpers (only needed by run_db_flow)
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

# Python: query credential DB, read key, decrypt CLIENT_SECRET
# Input:  VIDB_FQDN_ENV environment variable
# Output: plaintext CLIENT_SECRET printed to stdout
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

# Python: find and delete SSO domain row from kv_vidb_sso_domain
# Input:  SSO_DOMAIN_ID_ENV environment variable
# Output: prints "DELETED" on success, exits non-zero on failure
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

# Runs a Python script locally with the given KEY=VALUE environment variable.
# Sets STEP_OUTPUT global.
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
# "db" flow — same behavior as update-vidb-vcf-instance.sh
# =============================================================================
run_db_flow() {
  log_info "VCF Instance   : ${TARGET_VCF_ID}"
  [[ -n "$SSO_REALM_ID" ]] && log_info "SSO Realm ID   : ${SSO_REALM_ID}"

  # --------------------------------------------------------------------------
  # Step 1: Acquire Auth Token
  # --------------------------------------------------------------------------
  log_step "Step 1/${TOTAL_STEPS}  Acquiring auth token"
  acquire_token

  # --------------------------------------------------------------------------
  # Step 2: Resolve Management VC GUID
  # --------------------------------------------------------------------------
  log_step "Step 2/${TOTAL_STEPS}  Resolving management VC GUID for vcfInstanceId"
  MGMT_VC_GUID=$(resolve_mgmt_vc_guid "$TARGET_VCF_ID")
  log_ok "Management VC GUID: ${MGMT_VC_GUID}"

  # --------------------------------------------------------------------------
  # Step 3: Find External VIDB Record
  # --------------------------------------------------------------------------
  log_step "Step 3/${TOTAL_STEPS}  Finding external VIDB record for '${VIDB_FQDN}'"
  EXT_VIDB=$(fetch_ext_vidb_record "$VIDB_FQDN")

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
  # --------------------------------------------------------------------------
  log_step "Step 5/${TOTAL_STEPS}  Updating external VIDB (PUT)"

  PUT_PAYLOAD=$(jq -n \
    --arg id                 "$EXT_VIDB_ID" \
    --arg vidbResourceId     "$VIDB_RESOURCE_ID" \
    --arg vidbHost           "$VIDB_FQDN" \
    --arg vcGUID             "$MGMT_VC_GUID" \
    --arg vcfInstanceId      "$TARGET_VCF_ID" \
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
    log_info "  New VCF Instance : ${TARGET_VCF_ID}"
    log_info "  New VC GUID      : ${MGMT_VC_GUID}"
  else
    log_error "PUT failed (HTTP ${HTTP_CODE})"
    log_error "Response: $(echo "$HTTP_BODY" | jq -r '.message // .' 2>/dev/null || echo "$HTTP_BODY")"
    exit 1
  fi

  # --------------------------------------------------------------------------
  # Step 6: Update Collector for External VIDB Adapter
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
  # Step 8: Remove SSO Domain Config from DB  [only if --sso-realm given]
  # --------------------------------------------------------------------------
  if [[ -z "$SSO_REALM_ID" ]]; then
    log_info "No --sso-realm provided — skipping SSO domain removal."
    echo ""
    log_ok "All ${TOTAL_STEPS} steps completed successfully"
    return 0
  fi

  log_step "Step 8/${TOTAL_STEPS}  Removing SSO domain config from kv_vidb_sso_domain"
  log_info "  SSO Realm ID : ${SSO_REALM_ID}"

  PY6=$(mktemp /tmp/vidb_step8_XXXX.py)
  # shellcheck disable=SC2064
  trap "rm -f '$PY6'" EXIT
  write_step6_python "$PY6"

  STEP_OUTPUT=""
  run_db_python "$PY6" "SSO_DOMAIN_ID_ENV=${SSO_REALM_ID}" || exit 1

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

# =============================================================================
# "api" flow — same behavior as move-vidb-api.sh
# =============================================================================
run_api_flow() {
  log_info "Target VCF      : ${TARGET_VCF_ID}"
  log_info "SSO Realm       : ${SSO_REALM_ID}"

  # --------------------------------------------------------------------------
  # Step 1: Acquire Auth Token
  # --------------------------------------------------------------------------
  log_step "Step 1/${TOTAL_STEPS}  Acquiring auth token"
  acquire_token

  # --------------------------------------------------------------------------
  # Step 2: Fetch External VIDB Record and Discover Current Configuration
  # --------------------------------------------------------------------------
  log_step "Step 2/${TOTAL_STEPS}  Fetching VIDB record and discovering current configuration"
  EXT_VIDB=$(fetch_ext_vidb_record "$VIDB_FQDN")

  EXT_VIDB_ID=$(echo "$EXT_VIDB"                | jq -r '.id')
  CURRENT_VCF_INSTANCE_ID=$(echo "$EXT_VIDB"    | jq -r '.vcfInstanceId // empty')
  CURRENT_MGMT_VC_GUID=$(echo "$EXT_VIDB"       | jq -r '.vcGUID // empty')
  CURRENT_COLLECTOR_ID=$(echo "$EXT_VIDB"       | jq -r '.collectorId // empty')

  log_ok "External VIDB found: ${EXT_VIDB_ID}"
  log_info "  VIDB Host              : ${VIDB_FQDN}"
  log_info "  Current VCF Instance   : ${CURRENT_VCF_INSTANCE_ID}"
  log_info "  Target VCF Instance    : ${TARGET_VCF_ID}"
  log_info "  Current MGMT VC GUID   : ${CURRENT_MGMT_VC_GUID}"
  log_info "  Current Collector ID   : ${CURRENT_COLLECTOR_ID}"

  # --------------------------------------------------------------------------
  # Step 3: Resolve Management VC GUID for Target VCF
  # --------------------------------------------------------------------------
  log_step "Step 3/${TOTAL_STEPS}  Resolving management VC GUID for target VCF"
  TARGET_MGMT_VC_GUID=$(resolve_mgmt_vc_guid "$TARGET_VCF_ID")
  log_ok "Target Management VC GUID: ${TARGET_MGMT_VC_GUID}"

  # --------------------------------------------------------------------------
  # Step 4: Verify Pre-conditions
  # --------------------------------------------------------------------------
  log_step "Step 4/${TOTAL_STEPS}  Verifying pre-conditions"

  SHOULD_PATCH=true

  # Check if VCF instance needs updating
  if [[ "$CURRENT_VCF_INSTANCE_ID" == "$TARGET_VCF_ID" ]]; then
    log_warn "Current VCF instance already matches target VCF instance"
    SHOULD_PATCH=false
  fi

  # Check if management VC GUID needs updating
  if [[ "$CURRENT_MGMT_VC_GUID" == "$TARGET_MGMT_VC_GUID" ]]; then
    log_warn "Current management VC GUID already matches target GUID"
    SHOULD_PATCH=false
  fi

  log_info "VCF PATCH needed: ${SHOULD_PATCH}"
  log_info "Collector update will be checked in Step 5.5 regardless of PATCH status"

  if [[ "$SHOULD_PATCH" == false ]]; then
    log_info "Skipping PATCH — VCF instance and management VC GUID already match target"
    log_info "Note: Collector consistency will still be verified in Step 5.5"
  else
    log_info "Pre-conditions verified — proceeding with PATCH"
  fi

  # --------------------------------------------------------------------------
  # Step 5: PATCH External VIDB Association
  # --------------------------------------------------------------------------
  log_step "Step 5/${TOTAL_STEPS}  Updating external VIDB (PATCH)"

  if [[ "$SHOULD_PATCH" == true ]]; then
    PATCH_PAYLOAD=$(jq -n \
      --arg id        "$EXT_VIDB_ID" \
      --arg vcGUID    "$TARGET_MGMT_VC_GUID" \
      '{
        id:        $id,
        vcGUID:    $vcGUID
      }')

    log_info "PATCH payload: $(echo "$PATCH_PAYLOAD" | jq -c '.')"

    HTTP_CODE="" HTTP_BODY=""
    ops_internal_with_status PATCH "vidb/vmsp/${EXT_VIDB_ID}" -d "$PATCH_PAYLOAD"

    if [[ "$HTTP_CODE" =~ ^2 ]]; then
      log_ok "External VIDB updated (HTTP ${HTTP_CODE})"
      log_info "  VIDB ID                : ${EXT_VIDB_ID}"
      log_info "  New Management VC GUID : ${TARGET_MGMT_VC_GUID}"
    else
      log_error "PATCH failed (HTTP ${HTTP_CODE})"
      log_error "Response: $(echo "$HTTP_BODY" | jq -r '.message // .' 2>/dev/null || echo "$HTTP_BODY")"
      exit 1
    fi
  else
    log_ok "Skipped PATCH — no changes needed"
  fi

  # --------------------------------------------------------------------------
  # Step 5.5: Check and Update Collector (Always Checked)
  # --------------------------------------------------------------------------
  log_step "Step 5.5/${TOTAL_STEPS}  Checking collector consistency (mandatory)"

  log_info "  [5.5a] Fetching current VIDB adapter via public API"

  CURRENT_ADAPTER=$(ops_public GET "api/adapters/${EXT_VIDB_ID}?_no_links=true")

  CURRENT_ADAPTER_COLLECTOR_ID=$(echo "$CURRENT_ADAPTER" | jq -r '.collectorId // empty')

  if [[ -z "$CURRENT_ADAPTER_COLLECTOR_ID" ]]; then
    log_error "Failed to fetch current VIDB adapter (id: ${EXT_VIDB_ID})"
    log_error "Response: $(echo "$CURRENT_ADAPTER" | jq -r '.message // .' 2>/dev/null || echo "$CURRENT_ADAPTER")"
    exit 1
  fi

  log_info "  Current adapter collector ID: ${CURRENT_ADAPTER_COLLECTOR_ID}"
  log_info "  Target MGMT VC GUID        : ${TARGET_MGMT_VC_GUID}"

  log_info "  [5.5b] Fetching VMWARE adapter list to resolve target collector"
  VC_ADAPTERS=$(ops_public GET "api/adapters?adapterKindKey=VMWARE&_no_links=true")

  TARGET_ADAPTER_COLLECTOR_ID=$(echo "$VC_ADAPTERS" | jq -r \
    --arg vcguid "$TARGET_MGMT_VC_GUID" \
    '(.adapterInstancesInfoDto // [])[] |
     select((.resourceKey.resourceIdentifiers // [])[] |
       .identifierType.name == "VMEntityVCID" and .value == $vcguid) |
     .collectorId // empty')

  if [[ -z "$TARGET_ADAPTER_COLLECTOR_ID" ]]; then
    log_error "No VMWARE adapter found with VMEntityVCID = ${TARGET_MGMT_VC_GUID}"
    log_warn "Available VMWARE adapters:"
    echo "$VC_ADAPTERS" | jq -r \
      '(.adapterInstancesInfoDto // [])[] | "  \(.resourceKey.name)  collectorId=\(.collectorId)"' \
      2>/dev/null || echo "$VC_ADAPTERS"
    exit 1
  fi

  log_info "  Target adapter collector ID: ${TARGET_ADAPTER_COLLECTOR_ID}"
  log_info "  Comparing collectors:"
  log_info "    Current: ${CURRENT_ADAPTER_COLLECTOR_ID}"
  log_info "    Target:  ${TARGET_ADAPTER_COLLECTOR_ID}"

  if [[ "$CURRENT_ADAPTER_COLLECTOR_ID" == "$TARGET_ADAPTER_COLLECTOR_ID" ]]; then
    log_ok "Adapters collectors match — no update needed"
  else
    log_warn "Adapter collector mismatch detected — updating"
    log_info "  [5.5c] Updating VIDB adapter collector via public API"

    UPDATED_ADAPTER=$(echo "$CURRENT_ADAPTER" | jq \
      --argjson cid "$TARGET_ADAPTER_COLLECTOR_ID" '.collectorId = $cid')

    log_info "  Updating adapter collectorId to: ${TARGET_ADAPTER_COLLECTOR_ID}"

    HTTP_CODE="" HTTP_BODY=""
    ops_public_with_status PUT "api/adapters?_no_links=true" -d "$UPDATED_ADAPTER"

    if [[ "$HTTP_CODE" =~ ^2 ]]; then
      log_ok "VIDB adapter collector updated (HTTP ${HTTP_CODE})"
      log_info "  Updated collector ID : ${TARGET_ADAPTER_COLLECTOR_ID}"
    else
      log_error "Adapter update failed (HTTP ${HTTP_CODE})"
      log_error "Response: $(echo "$HTTP_BODY" | jq -r '.message // .' 2>/dev/null || echo "$HTTP_BODY")"
      exit 1
    fi

    log_info "  [5.5d] Verifying adapter collector update"

    sleep 2

    VERIFY_ADAPTER=$(ops_public GET "api/adapters/${EXT_VIDB_ID}?_no_links=true")
    VERIFIED_ADAPTER_COLLECTOR_ID=$(echo "$VERIFY_ADAPTER" | jq -r '.collectorId // empty')

    log_info "  Verified adapter collector ID (1st check): ${VERIFIED_ADAPTER_COLLECTOR_ID}"

    if [[ "$VERIFIED_ADAPTER_COLLECTOR_ID" == "$TARGET_ADAPTER_COLLECTOR_ID" ]]; then
      log_ok "Adapter collector verified: collectorId=${VERIFIED_ADAPTER_COLLECTOR_ID}"

      log_info "  [5.5e] Double-checking collector update persistence"
      sleep 1

      FINAL_VERIFY_ADAPTER=$(ops_public GET "api/adapters/${EXT_VIDB_ID}?_no_links=true")
      FINAL_VERIFIED_COLLECTOR_ID=$(echo "$FINAL_VERIFY_ADAPTER" | jq -r '.collectorId // empty')

      log_info "  Verified adapter collector ID (2nd check): ${FINAL_VERIFIED_COLLECTOR_ID}"

      if [[ "$FINAL_VERIFIED_COLLECTOR_ID" == "$TARGET_ADAPTER_COLLECTOR_ID" ]]; then
        log_ok "Collector update PERSISTED and confirmed: collectorId=${FINAL_VERIFIED_COLLECTOR_ID}"
      else
        log_warn "Collector verification discrepancy: 1st check=${VERIFIED_ADAPTER_COLLECTOR_ID}, 2nd check=${FINAL_VERIFIED_COLLECTOR_ID}"
      fi
    else
      log_warn "Adapter collector verification: expected ${TARGET_ADAPTER_COLLECTOR_ID}, got ${VERIFIED_ADAPTER_COLLECTOR_ID}"
      log_info "  (May require additional propagation time)"
    fi
  fi

  # --------------------------------------------------------------------------
  # Step 6: Poll for VIDB Eligibility
  # --------------------------------------------------------------------------
  log_step "Step 6/${TOTAL_STEPS}  Waiting for VIDB to become eligible (timeout: ${POLL_TIMEOUT}s)"
  log_info "  Polling every ${POLL_INTERVAL}s for VIDB ID=${EXT_VIDB_ID}"

  elapsed=0
  ELIGIBILITY_STATUS=""
  VIDB_VCF_ID=""

  while [[ $elapsed -lt $POLL_TIMEOUT ]]; do
    VMSP_VIDBS=$(ops_internal GET "vidb/vmsp/vidbs" 2>/dev/null || true)

    VIDB_RECORD=$(echo "$VMSP_VIDBS" | jq \
      --arg vid "$EXT_VIDB_ID" '.externalVidbs[] | select(.id == $vid)' 2>/dev/null || true)

    if [[ -n "$VIDB_RECORD" ]]; then
      VIDB_VCF_ID=$(echo "$VIDB_RECORD" | jq -r '.vcfInstanceId // empty')
      ELIGIBILITY_STATUS=$(echo "$VIDB_RECORD" | jq -r '.eligibilityStatus // empty')

      if [[ "$VIDB_VCF_ID" == "$TARGET_VCF_ID" ]]; then
        log_ok "VIDB is associated with target VCF instance (elapsed: ${elapsed}s)"
        log_info "  VIDB ID          : ${EXT_VIDB_ID}"
        log_info "  VCF Instance ID  : ${VIDB_VCF_ID}"
        break
      fi
    fi

    if [[ -n "$ELIGIBILITY_STATUS" ]]; then
      log_info "  Status: ${ELIGIBILITY_STATUS} — ${elapsed}s elapsed, retrying in ${POLL_INTERVAL}s..."
    else
      log_info "  Not yet visible with target VCF — ${elapsed}s elapsed, retrying in ${POLL_INTERVAL}s..."
    fi

    sleep "$POLL_INTERVAL"
    elapsed=$((elapsed + POLL_INTERVAL))
  done

  if [[ "$VIDB_VCF_ID" != "$TARGET_VCF_ID" ]]; then
    log_error "Timed out after ${POLL_TIMEOUT}s — VIDB did not associate with target VCF"
    log_warn "Expected VCF instance: ${TARGET_VCF_ID}, Got: ${VIDB_VCF_ID:-<not found>}"
    exit 1
  fi

  # --------------------------------------------------------------------------
  # Step 7: Update SSO Realm
  # --------------------------------------------------------------------------
  log_step "Step 7/${TOTAL_STEPS}  Updating SSO Realm VCF instance ID"

  log_info "  [7a] Verifying SSO Realm exists"
  HTTP_CODE="" HTTP_BODY=""
  ops_internal_with_status GET "vidb/ssodomains/${SSO_REALM_ID}"

  if [[ ! "$HTTP_CODE" =~ ^2 ]]; then
    log_error "Failed to fetch SSO Realm (HTTP ${HTTP_CODE})"
    log_error "Response: $(echo "$HTTP_BODY" | jq -r '.message // .' 2>/dev/null || echo "$HTTP_BODY")"
    exit 1
  fi
  log_ok "SSO Realm verified to exist"

  log_info "  [7b] Patching SSO Realm with target VCF instance ID"
  SSO_PATCH_PAYLOAD=$(jq -n \
    --arg id              "$SSO_REALM_ID" \
    --arg vcfInstanceId   "$TARGET_VCF_ID" \
    '{
      id:              $id,
      vcfInstanceId:   $vcfInstanceId
    }')

  HTTP_CODE="" HTTP_BODY=""
  ops_internal_with_status PATCH "vidb/ssodomains" -d "$SSO_PATCH_PAYLOAD"

  if [[ "$HTTP_CODE" =~ ^2 ]]; then
    log_ok "SSO Realm updated (HTTP ${HTTP_CODE})"
    log_info "  SSO Realm ID    : ${SSO_REALM_ID}"
    log_info "  New VCF Instance : ${TARGET_VCF_ID}"
  else
    log_error "SSO Realm PATCH failed (HTTP ${HTTP_CODE})"
    log_error "Response: $(echo "$HTTP_BODY" | jq -r '.message // .' 2>/dev/null || echo "$HTTP_BODY")"
    exit 1
  fi

  # --------------------------------------------------------------------------
  # Success
  # --------------------------------------------------------------------------
  echo ""
  log_ok "All ${TOTAL_STEPS} steps completed successfully"
  echo ""
  echo -e "${GREEN}Summary:${NC}"
  echo -e "  VIDB ID              : ${EXT_VIDB_ID}"
  echo -e "  Current VCF Instance : ${CURRENT_VCF_INSTANCE_ID}"
  echo -e "  Target VCF Instance  : ${TARGET_VCF_ID}"
  echo -e "  VIDB Host            : ${VIDB_FQDN}"
  echo -e "  SSO Realm ID         : ${SSO_REALM_ID}"
  echo ""
}

# =============================================================================
# Main — resolves the feature flag, validates flow-specific args, dispatches
# =============================================================================
main() {
  parse_args "$@"
  prompt_for_password
  check_deps

  echo -e "\n${BOLD}╔════════════════════════════════════════════════════╗${NC}"
  echo -e   "${BOLD}║        VIDB VCF Instance Migration (auto flow)     ║${NC}"
  echo -e   "${BOLD}╚════════════════════════════════════════════════════╝${NC}"
  log_info "OPS Host       : ${OPS_HOST}"
  log_info "VIDB Host      : ${VIDB_FQDN}"

  local flow
  flow=$(determine_flow)
  log_step "Feature flag resolved: VIDB_MIGRATION_FLOW=${flow}"

  case "$flow" in
    db)
      command -v python3 &>/dev/null || {
        log_error "python3 is required for the 'db' flow"; exit 1;
      }
      TOTAL_STEPS=7
      [[ -n "$SSO_REALM_ID" ]] && TOTAL_STEPS=8
      run_db_flow
      ;;
    api)
      [[ -n "$SSO_REALM_ID" ]] || {
        log_error "'api' flow (version > 9.1.0) requires --sso-realm"; exit 1;
      }
      TOTAL_STEPS=7
      run_api_flow
      ;;
    *)
      log_error "Unknown flow: ${flow}"
      exit 1
      ;;
  esac
}

# Only run main when executed directly — allows this file to be sourced by
# tests without triggering the full migration.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi

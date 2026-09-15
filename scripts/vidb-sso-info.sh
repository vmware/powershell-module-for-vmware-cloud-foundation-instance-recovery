#!/bin/bash
# =============================================================================
# vidb-sso-info.sh
#
# Purpose: Fetch VIDB <-> VCF instance <-> SSO Realm mapping data from Ops
# and print it as two separate, bordered reference tables (never merged):
#
#   Table 1 - from GET /suite-api/internal/vidb/vidbs
#     VIDB FQDN | VCF Instance ID | SSO Realm ID
#
#   Table 2 - from GET /suite-api/api/fleet-management/iam/ssorealms
#     VIDB ID | VCF ID | SSO Realm ID | SSO Realm Name
#
# Any field missing from a given record is printed as a highlighted "—"
# rather than causing an error, so gaps are easy to spot at a glance.
#
# Usage:
#   ./vidb-sso-info.sh --ops-fqdn <OPS_FQDN>
#
# Prerequisites: curl, python3
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

OPS_FQDN=""
ADMIN_USER="admin"
ADMIN_PASSWORD=""

usage() {
  cat <<EOF
${BOLD}Usage:${NC}
  $(basename "$0") --ops-fqdn <OPS_FQDN>

${BOLD}Description:${NC}
  Fetches VIDB <-> VCF instance <-> SSO Realm mapping from Ops and prints
  two separate tables:
    1. From /suite-api/internal/vidb/vidbs
       -> VIDB FQDN, VCF Instance ID, SSO Realm ID
    2. From /suite-api/api/fleet-management/iam/ssorealms
       -> VIDB ID, VCF ID, SSO Realm ID, SSO Realm Name
  Missing fields are printed as a highlighted "—" rather than causing an error.

${BOLD}Options:${NC}
  --ops-fqdn   Ops platform FQDN   [required]
  --help, -h   Show this help

${BOLD}Note:${NC}
  Admin password is prompted interactively from stdin.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ops-fqdn) OPS_FQDN="$2"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) log_error "Unknown option: $1"; echo; usage; exit 1 ;;
  esac
done

[[ -n "$OPS_FQDN" ]] || { log_error "Missing required argument: --ops-fqdn"; echo; usage; exit 1; }

read -sp "Enter Ops Admin Password: " ADMIN_PASSWORD
echo ""

get_ops_token() {
    local response
    response=$(curl -k -s --request POST \
        --url "https://${OPS_FQDN}/suite-api/api/auth/token/acquire" \
        --header 'content-type: application/json' \
        --data "{\"username\": \"${ADMIN_USER}\", \"authSource\": \"LOCAL\", \"password\": \"${ADMIN_PASSWORD}\"}")

    OPS_TOKEN=$(echo "$response" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

    if [ -z "$OPS_TOKEN" ]; then
        log_error "Failed to acquire Ops token"
        echo "Response: $response"
        exit 1
    fi
}

# All calls go through the internal/unsupported header set, per request.
ops_internal_get() {
    curl -k -s --request GET \
        --url "https://${OPS_FQDN}$1" \
        --header 'accept: application/json' \
        --header "authorization: vRealizeOpsToken ${OPS_TOKEN}" \
        --header 'content-type: application/json' \
        --header 'x-vrealizeops-api-use-unsupported: true'
}

# Renders a bordered, colored table from JSON of shape:
#   {"headers": ["Col1", ...], "rows": [["val1", ...], ...]}
# Empty cell values are shown as a highlighted "—".
render_table() {
    python3 -c '
import json, sys

CYAN = "\033[0;36m"
BOLD = "\033[1m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"
MISSING = "—"

data = json.loads(sys.stdin.read())
headers = data["headers"]
rows = data["rows"]

widths = []
for i, h in enumerate(headers):
    w = len(h)
    for r in rows:
        w = max(w, len(r[i] if r[i] else MISSING))
    widths.append(w)

def border(left, mid, right):
    return CYAN + left + mid.join("─" * (w + 2) for w in widths) + right + RESET

def line(cells, colors):
    sep = f"{CYAN}│{RESET}"
    parts = []
    for c, w, col in zip(cells, widths, colors):
        padded = c.ljust(w)
        parts.append(f" {col}{padded}{RESET} " if col else f" {padded} ")
    return sep + sep.join(parts) + sep

print(border("┌", "┬", "┐"))
print(line(list(headers), [BOLD + CYAN] * len(headers)))
print(border("├", "┼", "┤"))
for r in rows:
    cells = [c if c else MISSING for c in r]
    colors = [YELLOW if not c else "" for c in r]
    print(line(cells, colors))
print(border("└", "┴", "┘"))
if not rows:
    print(f"{YELLOW}  (no data found){RESET}")
'
}

print_vidb_table() {
    local raw="$1" transformed
    echo ""
    echo -e "${BOLD}${BLUE}Table 1: VIDB -> VCF Instance -> SSO Realm${NC}  (GET /suite-api/internal/vidb/vidbs)"

    transformed=$(echo "$raw" | python3 -c '
import json, sys
data = json.loads(sys.stdin.read())
rows = [[str(v.get("fqdn") or ""), str(v.get("vcfInstanceId") or ""), str(v.get("ssoDomainId") or "")] for v in data]
print(json.dumps({"headers": ["VIDB FQDN", "VCF Instance ID", "SSO Realm ID"], "rows": rows}))
' 2>&1) || { log_error "Failed to parse VIDB response: ${transformed}"; return; }

    echo "$transformed" | render_table
}

print_sso_realm_table() {
    local raw="$1" transformed
    echo ""
    echo -e "${BOLD}${BLUE}Table 2: VIDB -> VCF -> SSO Realm${NC}  (GET /suite-api/api/fleet-management/iam/ssorealms)"

    transformed=$(echo "$raw" | python3 -c '
import json, sys
data = json.loads(sys.stdin.read())
realms = data.get("ssoRealms", [])
rows = [[str(r.get("vidbResourceId") or ""), str(r.get("vcfInstanceId") or ""), str(r.get("id") or ""), str(r.get("name") or "")] for r in realms]
print(json.dumps({"headers": ["VIDB ID", "VCF ID", "SSO Realm ID", "SSO Realm Name"], "rows": rows}))
' 2>&1) || { log_error "Failed to parse SSO Realm response: ${transformed}"; return; }

    echo "$transformed" | render_table
}

main() {
    log_info "Fetching VIDB <-> VCF <-> SSO Realm mapping from ${OPS_FQDN}..."
    get_ops_token
    log_ok "Token acquired"

    VIDBS_RESPONSE=$(ops_internal_get "/suite-api/internal/vidb/vidbs")
    print_vidb_table "$VIDBS_RESPONSE"

    SSOREALMS_RESPONSE=$(ops_internal_get "/suite-api/api/fleet-management/iam/ssorealms")
    print_sso_realm_table "$SSOREALMS_RESPONSE"

    echo ""
}

main

#!/usr/bin/env bash
#
# Update a VCFMS component's ingress VIPs via the VMSP apply API.
#
# Supported component types: vcfa, vidb, ops-logs
#
# This script:
#   1. Authenticates with the VMSP platform API
#   2. Finds the installed component ID by type
#   3. Calls POST /api/v1/components/{componentId}?action=apply with only
#      the new ingress.<component>.vips.ipv4 array
#
# Usage:
#   ./update-component-vip.sh --platform-url https://vmsp.example.com \
#       --password 'secret' --component-type vcfa --vips 10.0.0.5,10.0.0.6

set -uo pipefail

PLATFORM_URL=""
ADMIN_USERNAME="admin@vsp.local"
ADMIN_PASSWORD=""
COMPONENT_TYPE=""
VIPS=""
POLL_INTERVAL=30
TASK_TIMEOUT=7200
DRY_RUN=false
TOKEN=""

# Valid component types and their corresponding:
#   [0] ingress JSON key  (ingress.<key>.vips.ipv4)
#   [1] PackageDeployment name (for kubectl backup)
declare -A COMPONENT_INGRESS_KEY=(
    [vcfa]="vcfa"
    [vidb]="vidb"
    [ops-logs]="ops-logs"
)
declare -A COMPONENT_PD_NAME=(
    [vcfa]="vcfa-bundle"
    [vidb]="vidb-bundle"
    [ops-logs]="ops-logs-bundle"
)

ALLOWED_TYPES="vcfa, vidb, ops-logs"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log()      { echo -e "${CYAN}[$(ts)]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[$(ts)]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[$(ts)]${NC} $*"; }
log_err()  { echo -e "${RED}[$(ts)]${NC} $*"; }

usage() {
    cat <<EOF
Usage: update-component-vip.sh [options]

Required:
  --platform-url   <url>          VMSP platform URL (e.g. https://vmsp.example.com)
  --password       <pass>         Admin password
  --component-type <type>         Component type: ${ALLOWED_TYPES}
  --vips           <ip,ip,...>    Comma-separated new VIPs (1-3 IPs)

Optional:
  --username       <user>         Admin username (default: admin@vsp.local)
  --poll-interval  <sec>          Task poll interval in seconds (default: 30)
  --timeout        <sec>          Max wait for task in seconds (default: 7200)
  --dry-run                       Print the payload and exit without calling the API
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform-url)   PLATFORM_URL="$2";    shift 2 ;;
        --username)       ADMIN_USERNAME="$2";  shift 2 ;;
        --password)       ADMIN_PASSWORD="$2";  shift 2 ;;
        --component-type) COMPONENT_TYPE="$2";  shift 2 ;;
        --vips)           VIPS="$2";            shift 2 ;;
        --poll-interval)  POLL_INTERVAL="$2";   shift 2 ;;
        --timeout)        TASK_TIMEOUT="$2";    shift 2 ;;
        --dry-run)        DRY_RUN=true;         shift ;;
        -h|--help)        usage ;;
        *)                log_err "Unknown option: $1"; usage ;;
    esac
done

[[ -z "$PLATFORM_URL" ]]    && { log_err "--platform-url is required";   usage; }
[[ -z "$ADMIN_PASSWORD" ]]  && { log_err "--password is required";       usage; }
[[ -z "$COMPONENT_TYPE" ]]  && { log_err "--component-type is required"; usage; }
[[ -z "$VIPS" ]]            && { log_err "--vips is required";           usage; }

# Validate component type
if [[ -z "${COMPONENT_INGRESS_KEY[$COMPONENT_TYPE]+_}" ]]; then
    log_err "Invalid component type '${COMPONENT_TYPE}'. Allowed values: ${ALLOWED_TYPES}"
    exit 1
fi

INGRESS_KEY="${COMPONENT_INGRESS_KEY[$COMPONENT_TYPE]}"
PD_NAME="${COMPONENT_PD_NAME[$COMPONENT_TYPE]}"
COMPONENT_UPPER="${COMPONENT_TYPE^^}"

PLATFORM_URL="${PLATFORM_URL%/}"

for cmd in curl jq kubectl; do
    command -v "$cmd" >/dev/null 2>&1 || { log_err "$cmd is required but not found"; exit 1; }
done

IFS=',' read -ra VIP_ARRAY <<< "$VIPS"
if [[ ${#VIP_ARRAY[@]} -eq 0 ]] || [[ ${#VIP_ARRAY[@]} -gt 3 ]]; then
    log_err "VIPs must contain 1-3 IP addresses, got ${#VIP_ARRAY[@]}"
    exit 1
fi

get_token() {
    local response
    response=$(curl -sk -XPOST "${PLATFORM_URL}/api/v1/identity/token" \
        --header 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode 'grant_type=password' \
        --data-urlencode "username=${ADMIN_USERNAME}" \
        --data-urlencode "password=${ADMIN_PASSWORD}" 2>/dev/null)

    TOKEN=$(echo "$response" | jq -r '.access_token // empty' 2>/dev/null)
    if [[ -z "$TOKEN" ]]; then
        log_err "Failed to get API token"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
        return 1
    fi
    log_ok "API token acquired"
}

poll_task() {
    local task_id="$1"
    local task_label="$2"
    local elapsed=0

    log "Polling task ${task_label} (${task_id}) every ${POLL_INTERVAL}s (timeout: ${TASK_TIMEOUT}s)..."

    while true; do
        local response
        response=$(curl -sk -XGET \
            -H "Authorization: Bearer ${TOKEN}" \
            "${PLATFORM_URL}/api/v1/tasks/${task_id}" 2>/dev/null)

        local status
        status=$(echo "$response" | jq -r '.status // .phase // "Unknown"' 2>/dev/null)

        case "$status" in
            Completed|Succeeded)
                log_ok "${task_label} completed successfully (${elapsed}s elapsed)"
                return 0
                ;;
            Failed|Error)
                log_err "${task_label} FAILED (${elapsed}s elapsed)"
                echo "$response" | jq '.' 2>/dev/null || echo "$response"
                return 1
                ;;
            *)
                if (( elapsed >= TASK_TIMEOUT )); then
                    log_err "${task_label} timed out after ${TASK_TIMEOUT}s (last status: ${status})"
                    echo "$response" | jq '.' 2>/dev/null || echo "$response"
                    return 1
                fi
                log "  ${task_label}: status=${status} (${elapsed}s elapsed)"
                sleep "$POLL_INTERVAL"
                elapsed=$(( elapsed + POLL_INTERVAL ))
                ;;
        esac
    done
}

# =========================================================================
# MAIN
# =========================================================================

log "============================================"
log "  Update ${COMPONENT_UPPER} Ingress VIPs"
log "============================================"
log ""

# --- Step 1: Authenticate and find component ---
log "Step 1: Finding ${COMPONENT_UPPER} component (type=${COMPONENT_TYPE})..."
get_token || exit 1

COMPONENTS_RESPONSE=$(curl -sk -XGET \
    -H "Authorization: Bearer ${TOKEN}" \
    "${PLATFORM_URL}/api/v1/components" 2>/dev/null)

COMPONENT_ID=$(echo "$COMPONENTS_RESPONSE" | \
    jq -r --arg type "$COMPONENT_TYPE" \
    '[.components[] | select(.type == $type)] | first | .id // empty' 2>/dev/null)

if [[ -z "$COMPONENT_ID" ]]; then
    log_err "No installed component found with type '${COMPONENT_TYPE}'"
    echo "$COMPONENTS_RESPONSE" | jq '.' 2>/dev/null || echo "$COMPONENTS_RESPONSE"
    exit 1
fi
log_ok "Found ${COMPONENT_UPPER} component: ${COMPONENT_ID}"

# --- Step 2: Backup the PackageDeployment ---
BACKUP_DIR="$(pwd)/${COMPONENT_TYPE}-vip-backup-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"

log "Step 2: Backing up ${PD_NAME} PackageDeployment to ${BACKUP_DIR}..."

if kubectl get pd "${PD_NAME}" -n prelude -o yaml > "${BACKUP_DIR}/${PD_NAME}-pd.yaml" 2>/dev/null; then
    log_ok "PackageDeployment backed up: ${BACKUP_DIR}/${PD_NAME}-pd.yaml"
    log "  Restore with: kubectl apply -f ${BACKUP_DIR}/${PD_NAME}-pd.yaml"
else
    log_warn "Could not back up ${PD_NAME} PackageDeployment (kubectl may not have access)"
    log_warn "Continuing without backup"
fi

# --- Step 3: Build the apply payload (VIPs only) ---
log "Step 3: Building apply payload for ingress key '${INGRESS_KEY}'..."

VIPS_JSON=$(printf '%s\n' "${VIP_ARRAY[@]}" | jq -R . | jq -sc .)

APPLY_PAYLOAD=$(jq -n \
    --arg key "$INGRESS_KEY" \
    --argjson vips "$VIPS_JSON" \
    '{
        spec: {
            configuration: {
                ingress: {
                    ($key): {
                        vips: {
                            ipv4: $vips
                        }
                    }
                }
            }
        }
    }')

log "Apply payload:"
echo "$APPLY_PAYLOAD" | jq '.'

if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "Dry run — exiting without calling the API"
    exit 0
fi

# --- Step 4: Call the apply API ---
log "Step 4: Calling apply API for ${COMPONENT_UPPER} component ${COMPONENT_ID}..."

get_token || exit 1

APPLY_RESPONSE=$(curl -sk -XPOST \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    "${PLATFORM_URL}/api/v1/components/${COMPONENT_ID}?action=apply" \
    -d "$APPLY_PAYLOAD" 2>/dev/null)

APPLY_TASK_ID=$(echo "$APPLY_RESPONSE" | jq -r '.id // empty' 2>/dev/null)

if [[ -z "$APPLY_TASK_ID" ]]; then
    log_err "Failed to create apply task"
    echo "$APPLY_RESPONSE" | jq '.' 2>/dev/null || echo "$APPLY_RESPONSE"
    exit 1
fi

log_ok "Apply task created: ${APPLY_TASK_ID}"

# --- Step 5: Poll task to completion ---
if poll_task "$APPLY_TASK_ID" "${COMPONENT_UPPER}-apply"; then
    echo ""
    log_ok "============================================"
    log_ok "  ${COMPONENT_UPPER} VIP UPDATE SUCCEEDED"
    log_ok "============================================"
    log_ok "Component ID: ${COMPONENT_ID}"
    log_ok "New VIPs:     ${VIP_ARRAY[*]}"
else
    echo ""
    log_err "============================================"
    log_err "  ${COMPONENT_UPPER} VIP UPDATE FAILED"
    log_err "============================================"
    log_err "Check the VMSP API task logs for details."
    exit 1
fi

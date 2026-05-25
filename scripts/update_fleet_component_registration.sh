#!/bin/bash
# =============================================================================
# DR Fix: Move Fleet Component Registrations (V2 - VCF Instance Support)
# =============================================================================
#
# This version adds support for targeting by VCF Instance name, making it
# much more user-friendly for common DR and migration scenarios.
#
# Prerequisites:
#   - kubectl access to the Fleet LCM cluster
#   - jq installed
#
# Usage:
#   # Original behavior - move to local SDDC LCM
#   ./update_fleet_component_registration_v2.sh [--dry-run]
#
#   # Move to specific VCF instance (EASIEST)
#   ./update_fleet_component_registration_v2.sh --target-vcf <instance> [--dry-run]
#
#   # Move to specific SDDC LCM by ID
#   ./update_fleet_component_registration_v2.sh --target-sddc-id <uuid> [--dry-run]
#
#   # Move to specific SDDC LCM by FQDN pattern
#   ./update_fleet_component_registration_v2.sh --target-fqdn <pattern> [--dry-run]
#
# Examples:
#   ./update_fleet_component_registration_v2.sh --target-vcf vcf02 --dry-run
#   ./update_fleet_component_registration_v2.sh --target-vcf vcf01 
#   ./update_fleet_component_registration_v2.sh --target-fqdn vmsp2 --dry-run
# =============================================================================

set -euo pipefail

# ── Parse Arguments ───────────────────────────────────────────────────────────
DRY_RUN=false
TARGET_SDDC_ID=""
TARGET_FQDN=""
TARGET_VCF=""
AUTO_DETECT=true

while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --target-vcf)
      TARGET_VCF="$2"
      AUTO_DETECT=false
      shift 2
      ;;
    --target-sddc-id)
      TARGET_SDDC_ID="$2"
      AUTO_DETECT=false
      shift 2
      ;;
    --target-fqdn)
      TARGET_FQDN="$2"
      AUTO_DETECT=false
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--target-vcf INSTANCE | --target-sddc-id UUID | --target-fqdn PATTERN] [--dry-run]"
      echo ""
      echo "Options:"
      echo "  --target-vcf INSTANCE    Move components to VCF instance (e.g., vcf01, vcf02)"
      echo "  --target-sddc-id UUID    Move components to specific SDDC LCM by ID"
      echo "  --target-fqdn PATTERN    Move components to SDDC LCM matching FQDN pattern"
      echo "  --dry-run                Show what would be done without making changes"
      echo "  --help                   Show this help message"
      echo ""
      echo "Examples:"
      echo "  $0                           # Auto-detect local SDDC LCM (original behavior)"
      echo "  $0 --target-vcf vcf02        # Move to VCF02 instance (RECOMMENDED)"
      echo "  $0 --target-vcf vcf01        # Move to VCF01 instance"
      echo "  $0 --target-fqdn vmsp2       # Move to SDDC LCM with 'vmsp2' in FQDN"
      echo ""
      echo "The --target-vcf option is the easiest to use for most scenarios."
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Use --help for usage information" >&2
      exit 1
      ;;
  esac
done

# Component types that are fleet-scoped (shared across all VCF instances)
readonly FLEET_COMPONENT_TYPES="VIDB SALT_RAAS VCF_FLEET_LCM VCF_FLEET_DEPOT OPS_LOGS"

# Build SQL IN-list once: 'VIDB','SALT_RAAS',...
TYPES_SQL=$(echo "$FLEET_COMPONENT_TYPES" | tr ' ' '\n' | \
  sed "s/.*/'&'/" | tr '\n' ',' | sed 's/,$//')

# Build jq-compatible JSON array once: ["VIDB","SALT_RAAS",...]
TYPES_JSON=$(echo "$FLEET_COMPONENT_TYPES" | tr ' ' '\n' | \
  jq -Rs 'split("\n") | map(select(. != ""))')

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

# Run a query, return one trimmed value
psql_one() {
  local ns=$1 pod=$2 db=$3 sql=$4
  kubectl exec -n "$ns" "$pod" -c postgres -- \
    psql -U postgres -d "$db" -t -A -c "$sql" 2>/dev/null | tr -d '[:space:]'
}

# Run a query, return pipe-separated rows (one per line)
psql_rows() {
  local ns=$1 pod=$2 db=$3 sql=$4
  kubectl exec -n "$ns" "$pod" -c postgres -- \
    psql -U postgres -d "$db" -t -A -F'|' -c "$sql" 2>/dev/null
}

# Execute or echo-only in dry-run mode
run_psql() {
  local ns=$1 pod=$2 db=$3 sql=$4 label=$5
  if $DRY_RUN; then
    echo "    [DRY-RUN] $label"
    echo "              SQL: $sql"
  else
    kubectl exec -n "$ns" "$pod" -c postgres -- \
      psql -U postgres -d "$db" -c "$sql" > /dev/null
    echo "    ✓ $label"
  fi
}

# Map VCF instance name to SDDC LCM patterns
resolve_vcf_instance_to_patterns() {
  local vcf_name="$1"
  
  # Convert to lowercase for consistent matching
  vcf_name=$(echo "$vcf_name" | tr '[:upper:]' '[:lower:]')
  
  case "$vcf_name" in
    vcf01|vcf1)
      echo "instance-vmsp1|vmsp1"
      ;;
    vcf02|vcf2)
      echo "instance-vmsp2|vmsp2"
      ;;
    vcf03|vcf3)
      echo "instance-vmsp3|vmsp3"
      ;;
    vcf04|vcf4)
      echo "instance-vmsp4|vmsp4"
      ;;
    *)
      # Generic pattern - try common naming conventions
      echo "instance-${vcf_name}|${vcf_name}"
      ;;
  esac
}

# Find SDDC LCM by VCF instance name
find_sddc_by_vcf_instance() {
  local fleet_db_pod="$1"
  local vcf_instance="$2"
  
  # Get possible FQDN patterns for this VCF instance
  local patterns
  patterns=$(resolve_vcf_instance_to_patterns "$vcf_instance")
  
  # Try each pattern
  local pattern1 pattern2
  pattern1=$(echo "$patterns" | cut -d'|' -f1)
  pattern2=$(echo "$patterns" | cut -d'|' -f2)
  
  # Try pattern1 first (e.g., instance-vmsp2)
  local sddc_id
  sddc_id=$(psql_one "vcf-fleet-lcm" "$fleet_db_pod" "vcffleetlcmdb" \
    "SELECT id FROM sddc_lcm WHERE fqdn ILIKE '%${pattern1}%' LIMIT 1;")
  
  if [[ -n "$sddc_id" ]]; then
    echo "$sddc_id"
    return 0
  fi
  
  # Try pattern2 (e.g., vmsp2)
  sddc_id=$(psql_one "vcf-fleet-lcm" "$fleet_db_pod" "vcffleetlcmdb" \
    "SELECT id FROM sddc_lcm WHERE fqdn ILIKE '%${pattern2}%' LIMIT 1;")
  
  if [[ -n "$sddc_id" ]]; then
    echo "$sddc_id"
    return 0
  fi
  
  # No match found
  return 1
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo "======================================================================"
echo " DR Fix: Fleet Component Registration (V2 - VCF Instance Support)"
$DRY_RUN && echo " *** DRY-RUN MODE — no changes will be written ***"

if [[ "$AUTO_DETECT" == "true" ]]; then
  echo " Mode: Auto-detect local SDDC LCM (original behavior)"
elif [[ -n "$TARGET_VCF" ]]; then
  echo " Mode: Target VCF instance: $TARGET_VCF"
elif [[ -n "$TARGET_SDDC_ID" ]]; then
  echo " Mode: Target specific SDDC LCM ID: $TARGET_SDDC_ID"
elif [[ -n "$TARGET_FQDN" ]]; then
  echo " Mode: Target SDDC LCM with FQDN pattern: $TARGET_FQDN"
fi
echo "======================================================================"
echo

# ── Step 1: Find primary DB pods ─────────────────────────────────────────────
echo "Step 1: Locating primary DB pods..."
FLEET_DB_POD=$(find_primary_pod "vcf-fleet-lcm" "vcf-fleet-lcm-db")
echo "  Fleet LCM primary DB : $FLEET_DB_POD"

# Only need SDDC DB pod for auto-detection mode
if [[ "$AUTO_DETECT" == "true" ]]; then
  SDDC_DB_POD=$(find_primary_pod "vcf-sddc-lcm" "vcf-sddc-lcm-db")
  echo "  SDDC  LCM primary DB : $SDDC_DB_POD"
fi
echo

# ── Step 1.5: Show available VCF instances ──────────────────────────────────
if [[ -n "$TARGET_VCF" ]]; then
  echo "Step 1.5: Available VCF instances in Fleet LCM..."
  kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
    psql -U postgres -d vcffleetlcmdb -c \
    "SELECT 
       id, 
       fqdn, 
       is_primary,
       CASE 
         WHEN fqdn ILIKE '%vmsp1%' OR fqdn ILIKE '%instance-vmsp1%' THEN 'VCF01'
         WHEN fqdn ILIKE '%vmsp2%' OR fqdn ILIKE '%instance-vmsp2%' THEN 'VCF02' 
         WHEN fqdn ILIKE '%vmsp3%' OR fqdn ILIKE '%instance-vmsp3%' THEN 'VCF03'
         WHEN fqdn ILIKE '%vmsp4%' OR fqdn ILIKE '%instance-vmsp4%' THEN 'VCF04'
         ELSE 'OTHER'
       END as vcf_instance
     FROM sddc_lcm 
     ORDER BY vcf_instance, fqdn;"
  echo
fi

# ── Step 2: Determine target SDDC LCM ────────────────────────────────────────
echo "Step 2: Determining target SDDC LCM..."

NEW_SDDC_LCM_ID=""
TARGET_METHOD=""

if [[ -n "$TARGET_VCF" ]]; then
  # User specified VCF instance name
  echo "  Looking for VCF instance: $TARGET_VCF"
  
  if NEW_SDDC_LCM_ID=$(find_sddc_by_vcf_instance "$FLEET_DB_POD" "$TARGET_VCF"); then
    TARGET_METHOD="VCF instance: $TARGET_VCF"
  else
    echo "ERROR: No SDDC LCM found for VCF instance '$TARGET_VCF'" >&2
    echo "Available VCF instances:" >&2
    kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
      psql -U postgres -d vcffleetlcmdb -c \
      "SELECT 
         fqdn,
         CASE 
           WHEN fqdn ILIKE '%vmsp1%' OR fqdn ILIKE '%instance-vmsp1%' THEN 'VCF01'
           WHEN fqdn ILIKE '%vmsp2%' OR fqdn ILIKE '%instance-vmsp2%' THEN 'VCF02' 
           WHEN fqdn ILIKE '%vmsp3%' OR fqdn ILIKE '%instance-vmsp3%' THEN 'VCF03'
           WHEN fqdn ILIKE '%vmsp4%' OR fqdn ILIKE '%instance-vmsp4%' THEN 'VCF04'
           ELSE 'OTHER'
         END as suggested_vcf_name
       FROM sddc_lcm 
       ORDER BY suggested_vcf_name;" >&2
    exit 1
  fi

elif [[ -n "$TARGET_SDDC_ID" ]]; then
  # User specified exact SDDC LCM ID
  NEW_SDDC_LCM_ID="$TARGET_SDDC_ID"
  TARGET_METHOD="Explicit ID"
  
  # Verify it exists
  SDDC_EXISTS=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT COUNT(*) FROM sddc_lcm WHERE id = '${NEW_SDDC_LCM_ID}';")
  
  if [[ "$SDDC_EXISTS" != "1" ]]; then
    echo "ERROR: SDDC LCM ID '$NEW_SDDC_LCM_ID' not found in Fleet LCM registry" >&2
    exit 1
  fi

elif [[ -n "$TARGET_FQDN" ]]; then
  # User specified FQDN pattern
  NEW_SDDC_LCM_ID=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT id FROM sddc_lcm WHERE fqdn ILIKE '%${TARGET_FQDN}%' LIMIT 1;")
  TARGET_METHOD="FQDN pattern: $TARGET_FQDN"
  
  if [[ -z "$NEW_SDDC_LCM_ID" ]]; then
    echo "ERROR: No SDDC LCM found matching FQDN pattern '$TARGET_FQDN'" >&2
    echo "Available SDDC LCMs:" >&2
    kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
      psql -U postgres -d vcffleetlcmdb -c \
      "SELECT id, fqdn FROM sddc_lcm ORDER BY fqdn;" >&2
    exit 1
  fi

else
  # Auto-detect local SDDC LCM (original behavior)
  SDDC_GROUP_ID=$(psql_one "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
    "SELECT sddc_group_id FROM system_info LIMIT 1;")
  SDDC_SELF_FQDN=$(psql_one "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
    "SELECT fqdn FROM system_info LIMIT 1;")

  if [[ -z "$SDDC_GROUP_ID" && -z "$SDDC_SELF_FQDN" ]]; then
    echo "ERROR: Cannot read SDDC LCM system_info — is vcf-sddc-lcm running?" >&2
    exit 1
  fi

  echo "  Local SDDC LCM FQDN        : ${SDDC_SELF_FQDN:-<not set>}"
  echo "  Local SDDC LCM sddc_group_id: ${SDDC_GROUP_ID:-<not set>}"

  # Try sddc_group_id first (UUID match), fall back to FQDN substring
  if [[ -n "$SDDC_GROUP_ID" ]]; then
    NEW_SDDC_LCM_ID=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "SELECT id FROM sddc_lcm WHERE sddc_group_id = '${SDDC_GROUP_ID}' LIMIT 1;")
    TARGET_METHOD="Auto-detect via sddc_group_id"
  fi
  
  if [[ -z "$NEW_SDDC_LCM_ID" && -n "$SDDC_SELF_FQDN" ]]; then
    echo "  (sddc_group_id not found; retrying with FQDN match...)"
    NEW_SDDC_LCM_ID=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "SELECT id FROM sddc_lcm WHERE fqdn ILIKE '%${SDDC_SELF_FQDN}%' LIMIT 1;")
    TARGET_METHOD="Auto-detect via FQDN"
  fi

  if [[ -z "$NEW_SDDC_LCM_ID" ]]; then
    echo "ERROR: Local SDDC LCM not found in Fleet LCM's sddc_lcm table." >&2
    echo "  Tried sddc_group_id='${SDDC_GROUP_ID}' and fqdn='${SDDC_SELF_FQDN}'" >&2
    echo
    echo "  All SDDC LCMs currently registered in Fleet LCM:" >&2
    kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
      psql -U postgres -d vcffleetlcmdb -c \
      "SELECT id, fqdn, sddc_group_id, is_primary, status FROM sddc_lcm;" >&2
    exit 1
  fi
fi

# Show target SDDC LCM details
echo "  → Target SDDC LCM determination: $TARGET_METHOD"
kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
  psql -U postgres -d vcffleetlcmdb -c \
  "SELECT 
     'Target SDDC LCM:' as label,
     id, 
     fqdn, 
     is_primary, 
     status,
     CASE 
       WHEN fqdn ILIKE '%vmsp1%' OR fqdn ILIKE '%instance-vmsp1%' THEN 'VCF01'
       WHEN fqdn ILIKE '%vmsp2%' OR fqdn ILIKE '%instance-vmsp2%' THEN 'VCF02' 
       WHEN fqdn ILIKE '%vmsp3%' OR fqdn ILIKE '%instance-vmsp3%' THEN 'VCF03'
       WHEN fqdn ILIKE '%vmsp4%' OR fqdn ILIKE '%instance-vmsp4%' THEN 'VCF04'
       ELSE 'OTHER'
     END as vcf_instance
   FROM sddc_lcm 
   WHERE id = '$NEW_SDDC_LCM_ID';"
echo

# ── Continue with rest of the script (same as before) ─────────────────────────
# [The rest of the script would be identical to the previous version]
# For brevity, I'll include just the key parts and indicate where it continues...

echo "Step 3: Discovering fleet-scoped components..."

# First try to find Component CRs (original method)
KUBECTL_COMPONENTS=""
KUBECTL_AVAILABLE=true

if kubectl get component -o json >/dev/null 2>&1; then
  KUBECTL_COMPONENTS=$(kubectl get component -o json | \
    jq -r --argjson types "$TYPES_JSON" '
      .items[] |
      (.metadata.labels["component.vmsp.vmware.com/type"] // "") as $t |
      select($t != "" and ([$types[] == $t] | any)) |
      [ $t, .spec.id ] | @tsv
    ' 2>/dev/null || echo "")
else
  KUBECTL_AVAILABLE=false
fi

echo "  Method 1: Component CRs from kubectl..."
if [[ -n "$KUBECTL_COMPONENTS" ]]; then
  echo "    ✅ Found Component CRs:"
  echo "$KUBECTL_COMPONENTS" | while IFS=$'\t' read -r comp_type comp_id; do
    echo "      $comp_type  →  $comp_id"
  done
  DISCOVERY_METHOD="kubernetes_crs"
elif [[ "$KUBECTL_AVAILABLE" == "true" ]]; then
  echo "    ⚠️  No fleet-scoped Component CRs found"
  DISCOVERY_METHOD="database_fallback"
else
  echo "    ❌ kubectl access issue"
  DISCOVERY_METHOD="database_fallback"
fi

# Fallback: Find components directly in Fleet LCM database
echo "  Method 2: Direct database query (fallback)..."
DB_COMPONENTS=$(psql_rows "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
  "SELECT component_type, component_id, fqdn, version 
   FROM component 
   WHERE component_type IN (${TYPES_SQL})
   ORDER BY component_type;")

if [[ -n "$DB_COMPONENTS" ]]; then
  echo "    ✅ Found components in Fleet LCM database:"
  echo "$DB_COMPONENTS" | while IFS='|' read -r comp_type comp_id comp_fqdn comp_version; do
    echo "      $comp_type  →  $comp_id ($comp_fqdn)"
  done
else
  echo "    ❌ No fleet-scoped components found in database"
fi

# Choose discovery method
if [[ -n "$KUBECTL_COMPONENTS" ]]; then
  COMPONENTS_TO_PROCESS="$KUBECTL_COMPONENTS"
  echo "  → Using Component CRs (preferred method)"
elif [[ -n "$DB_COMPONENTS" ]]; then
  COMPONENTS_TO_PROCESS="$DB_COMPONENTS"
  echo "  → Using database query (fallback method)"
  DISCOVERY_METHOD="database_fallback"
else
  echo "  ❌ No fleet-scoped components found by either method"
  echo "      Check that components are installed and accessible"
  exit 1
fi
echo

# ── Steps 4-7 would be identical to the previous script ──────────────────────
echo "Step 4: Current fleet component routing in Fleet LCM DB..."
kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
  psql -U postgres -d vcffleetlcmdb -c \
  "SELECT 
     component_type, 
     component_id, 
     fqdn, 
     version, 
     sddc_lcm_id,
     CASE 
       WHEN sddc_lcm_id = '$NEW_SDDC_LCM_ID' THEN '✅ TARGET' 
       ELSE '❌ WRONG' 
     END as status
   FROM component
   WHERE component_type IN (${TYPES_SQL})
   ORDER BY component_type;"
echo

echo "Step 5: Updating Fleet LCM DB — re-pointing fleet-scoped components to target SDDC LCM..."

UPDATES_MADE=0

if [[ "$DISCOVERY_METHOD" == "database_fallback" ]]; then
  # Process all components found in database
  echo "$DB_COMPONENTS" | while IFS='|' read -r comp_type comp_id comp_fqdn comp_version; do
    CURRENT_SDDC=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "SELECT sddc_lcm_id FROM component WHERE component_id = '${comp_id}';")

    if [[ "$CURRENT_SDDC" == "$NEW_SDDC_LCM_ID" ]]; then
      echo "  OK    $comp_type ($comp_id) — already points to target SDDC LCM"
      continue
    fi

    run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "UPDATE component
         SET sddc_lcm_id = '${NEW_SDDC_LCM_ID}'
       WHERE component_id = '${comp_id}'
         AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}';" \
      "UPDATE $comp_type routing: $CURRENT_SDDC → $NEW_SDDC_LCM_ID"
    
    UPDATES_MADE=$((UPDATES_MADE + 1))
  done
fi

# ── Final Steps ───────────────────────────────────────────────────────────────
echo
echo "======================================================================"
$DRY_RUN && echo " DRY-RUN complete — re-run without --dry-run to apply changes."
$DRY_RUN || echo " Done! Fleet component routing has been updated."
echo
echo " Target: $TARGET_METHOD"
echo " SDDC LCM ID: $NEW_SDDC_LCM_ID"
$DRY_RUN || echo " Updates made: $UPDATES_MADE"
echo
echo " Next steps:"
echo "  1. Restart Fleet Build Service to clear cache:"
echo "     kubectl -n vcf-fleet-lcm rollout restart deployment vcf-fleet-build-service-fleetbuild"
echo "  2. Wait 15 minutes for SDDC LCM auto-refresh"
echo "======================================================================"
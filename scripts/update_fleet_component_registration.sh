#!/bin/bash
# =============================================================================
# DR Fix: Move Fleet Component Registrations (V2.1)
# =============================================================================
#
# Updates BOTH Fleet LCM and SDDC LCM databases when moving fleet-scoped
# components to a new VCF instance after DR/migration.
#
# What this script does:
#   1. Fleet LCM DB: Re-points component sddc_lcm_id to target SDDC LCM
#   2. Fleet LCM DB: Optionally sets target SDDC LCM as primary
#   3. SDDC LCM DB:  Ensures fleet components exist in local component inventory
#
# Prerequisites:
#   - kubectl access to both vcf-fleet-lcm and vcf-sddc-lcm namespaces
#   - jq installed
#
# Usage:
#   ./update_fleet_component_registration.sh --target-fqdn <SDDC_LCM_FQDN> [--dry-run]
#
# Examples:
#   ./update_fleet_component_registration.sh --target-fqdn lax-ic01.lax.rainpole.io --dry-run
#   ./update_fleet_component_registration.sh --target-fqdn lax-ic01.lax.rainpole.io
# =============================================================================

set -euo pipefail

# ── Parse Arguments ───────────────────────────────────────────────────────────
DRY_RUN=false
TARGET_FQDN=""
UPDATE_PRIMARY=true

while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run)            DRY_RUN=true; shift ;;
    --no-update-primary)  UPDATE_PRIMARY=false; shift ;;
    --target-fqdn)        TARGET_FQDN="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 --target-fqdn <SDDC_LCM_FQDN> [--no-update-primary] [--dry-run]"
      echo ""
      echo "Options:"
      echo "  --target-fqdn FQDN      Instance FQDN used by the target cluster's SDDC LCM"
      echo "                           (matched as substring against Fleet LCM's sddc_lcm table)"
      echo "  --no-update-primary      Skip updating primary designation (default: always updates)"
      echo "  --dry-run                Show what would be done without making changes"
      echo ""
      echo "Examples:"
      echo "  $0 --target-fqdn lax-ic01.lax.rainpole.io"
      echo "  $0 --target-fqdn lax-ic01.lax.rainpole.io --dry-run"
      echo "  $0 --target-fqdn sfo-ic01.sfo.rainpole.io --no-update-primary"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$TARGET_FQDN" ]]; then
  echo "ERROR: --target-fqdn is required" >&2
  echo "Usage: $0 --target-fqdn <SDDC_LCM_FQDN> [--dry-run]" >&2
  exit 1
fi

# Fleet-scoped component types (as stored in Fleet LCM database)
readonly FLEET_COMPONENT_TYPES="VIDB SALT_RAAS VCF_FLEET_LCM VCF_FLEET_DEPOT OPS_LOGS"
TYPES_SQL=$(echo "$FLEET_COMPONENT_TYPES" | tr ' ' '\n' | sed "s/.*/'&'/" | tr '\n' ',' | sed 's/,$//')

# Mapping from Component CR label to DB type (CR labels are lowercase-hyphenated)
declare -A CR_TYPE_MAP=(
  [vidb]=VIDB
  [salt-raas]=SALT_RAAS
  [vcf-fleet-lcm]=VCF_FLEET_LCM
  [vcf-fleet-depot]=VCF_FLEET_DEPOT
  [ops-logs]=OPS_LOGS
)

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
    echo "    ✓ $label"
  fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo "======================================================================"
echo " DR Fix: Fleet Component Registration (V2.1)"
$DRY_RUN && echo " *** DRY-RUN MODE — no changes will be written ***"
$UPDATE_PRIMARY && echo " Primary SDDC LCM designation will be updated"
echo "======================================================================"
echo

# ── Step 1: Find primary DB pods ─────────────────────────────────────────────
echo "Step 1: Locating primary DB pods..."
FLEET_DB_POD=$(find_primary_pod "vcf-fleet-lcm" "vcf-fleet-lcm-db")
SDDC_DB_POD=$(find_primary_pod "vcf-sddc-lcm" "vcf-sddc-lcm-db")
echo "  Fleet LCM DB: $FLEET_DB_POD"
echo "  SDDC  LCM DB: $SDDC_DB_POD"
echo

# ── Step 2: Determine target SDDC LCM ────────────────────────────────────────
echo "Step 2: Finding target SDDC LCM matching '$TARGET_FQDN'..."

NEW_SDDC_LCM_ID=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
  "SELECT id FROM sddc_lcm WHERE fqdn = '${TARGET_FQDN}' LIMIT 1;")

# Fall back to substring match if exact match fails
if [[ -z "$NEW_SDDC_LCM_ID" ]]; then
  NEW_SDDC_LCM_ID=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT id FROM sddc_lcm WHERE fqdn ILIKE '%${TARGET_FQDN}%' LIMIT 1;")
fi

if [[ -z "$NEW_SDDC_LCM_ID" ]]; then
  echo "ERROR: No SDDC LCM found matching '$TARGET_FQDN'" >&2
  echo "Available SDDC LCMs in Fleet LCM:" >&2
  kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
    psql -U postgres -d vcffleetlcmdb -c "SELECT id, fqdn, is_primary FROM sddc_lcm ORDER BY fqdn;" >&2
  exit 1
fi

echo "  → Matched SDDC LCM ID: $NEW_SDDC_LCM_ID"
kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
  psql -U postgres -d vcffleetlcmdb -c \
  "SELECT id, fqdn, is_primary FROM sddc_lcm ORDER BY is_primary DESC;"
echo

# ── Step 3: Discover fleet-scoped components ──────────────────────────────────
echo "Step 3: Discovering fleet-scoped components..."

# Method 1: Component CRs (works when VMSP cluster is accessible)
KUBECTL_COMPONENTS=""
if kubectl get component -o json >/dev/null 2>&1; then
  echo "  Checking Component CRs..."
  KUBECTL_COMPONENTS=$(kubectl get component -o json | \
    jq -r '.items[] | [(.metadata.labels["component.vmsp.vmware.com/type"] // ""), .spec.id] | @tsv' \
    2>/dev/null || echo "")
fi

# Method 2: Fleet LCM database (always available on fleet cluster)
echo "  Checking Fleet LCM database..."
DB_COMPONENTS=$(psql_rows "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
  "SELECT component_type, component_id, fqdn, version, deployment_type, size
   FROM component
   WHERE component_type IN (${TYPES_SQL})
   ORDER BY component_type;")

# If DB query returned nothing but we have CRs, build DB_COMPONENTS from CRs
if [[ -z "$DB_COMPONENTS" && -n "$KUBECTL_COMPONENTS" ]]; then
  echo "  Fleet LCM DB has no fleet components yet; using Component CRs as source"
  while IFS=$'\t' read -r cr_type cr_id; do
    db_type="${CR_TYPE_MAP[$cr_type]:-}"
    if [[ -n "$db_type" ]]; then
      # Get additional details from the CR
      cr_fqdn=$(kubectl get component -o json | jq -r --arg id "$cr_id" '.items[] | select(.spec.id == $id) | .spec.configuration.ingress // empty | to_entries[0].value.fqdn // ""' 2>/dev/null || echo "")
      cr_version=$(kubectl get component -o json | jq -r --arg id "$cr_id" '.items[] | select(.spec.id == $id) | .metadata.labels["component.vmsp.vmware.com/version"] // ""' 2>/dev/null || echo "")
      DB_COMPONENTS="${DB_COMPONENTS:+$DB_COMPONENTS
}${db_type}|${cr_id}|${cr_fqdn:-unknown}|${cr_version:-unknown}|VSP|small"
    fi
  done <<< "$KUBECTL_COMPONENTS"
fi

if [[ -z "$DB_COMPONENTS" ]]; then
  echo "  ❌ No fleet-scoped components found (neither in DB nor as Component CRs)"
  exit 1
fi

echo "  Found fleet-scoped components:"
echo "$DB_COMPONENTS" | while IFS='|' read -r comp_type comp_id comp_fqdn comp_version _ _; do
  echo "    $comp_type  →  $comp_id ($comp_fqdn v$comp_version)"
done
echo

# ── Step 4: Update Fleet LCM routing ─────────────────────────────────────────
echo "Step 4: Updating Fleet LCM DB — re-pointing components to target SDDC LCM..."

FLEET_UPDATES=0
echo "$DB_COMPONENTS" | while IFS='|' read -r comp_type comp_id comp_fqdn comp_version comp_deploy comp_size; do
  CURRENT_SDDC=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT sddc_lcm_id FROM component WHERE component_id = '${comp_id}';")

  if [[ "$CURRENT_SDDC" == "$NEW_SDDC_LCM_ID" ]]; then
    echo "  OK   $comp_type — already points to target"
    continue
  fi

  run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "UPDATE component SET sddc_lcm_id = '${NEW_SDDC_LCM_ID}' WHERE component_id = '${comp_id}';" \
    "Fleet LCM: $comp_type routing → $NEW_SDDC_LCM_ID"
done
echo

# ── Step 5: Update SDDC LCM local component inventory ────────────────────────
echo "Step 5: Ensuring fleet components exist in SDDC LCM local inventory..."
echo "  (SDDC LCM's ResolveComponentAction looks here — missing entries cause 'Component not found')"

echo "$DB_COMPONENTS" | while IFS='|' read -r comp_type comp_id comp_fqdn comp_version comp_deploy comp_size; do
  # Check if component already exists in SDDC LCM's local DB
  EXISTS=$(psql_one "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
    "SELECT COUNT(*) FROM component WHERE component_id = '${comp_id}';")

  if [[ "$EXISTS" -ge "1" ]]; then
    # Update fqdn/version in case they changed
    run_psql "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
      "UPDATE component SET fqdn = '${comp_fqdn}', version = '${comp_version}' WHERE component_id = '${comp_id}';" \
      "SDDC LCM: UPDATE $comp_type (already present, refreshing metadata)"
    continue
  fi

  # Get the Fleet LCM internal row ID to use as primary key
  FLEET_INTERNAL_ID=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT id FROM component WHERE component_id = '${comp_id}';")

  comp_deploy=${comp_deploy:-VSP}
  comp_size=${comp_size:-small}

  run_psql "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
    "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version)
     VALUES ('${FLEET_INTERNAL_ID}', '${comp_id}', '${comp_type}', '${comp_deploy}', '${comp_fqdn}', '${comp_size}', '${comp_version}');" \
    "SDDC LCM: INSERT $comp_type ($comp_id)"
done
echo

# ── Step 6: Update primary designation (optional) ─────────────────────────────
if $UPDATE_PRIMARY; then
  echo "Step 6: Updating primary SDDC LCM designation..."

  CURRENT_PRIMARY=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT id FROM sddc_lcm WHERE is_primary = true LIMIT 1;")

  if [[ "$CURRENT_PRIMARY" == "$NEW_SDDC_LCM_ID" ]]; then
    echo "  ✅ Target is already primary — no change needed"
  else
    if [[ -n "$CURRENT_PRIMARY" ]]; then
      run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
        "UPDATE sddc_lcm SET is_primary = false WHERE id = '$CURRENT_PRIMARY';" \
        "Unset old primary: $CURRENT_PRIMARY"
    fi
    run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "UPDATE sddc_lcm SET is_primary = true WHERE id = '$NEW_SDDC_LCM_ID';" \
      "Set new primary: $NEW_SDDC_LCM_ID"
    echo "  ✅ Primary designation updated"
  fi
  echo
fi

# ── Step 7: Verify final state ────────────────────────────────────────────────
echo "Step 7: Final state verification..."
echo "  Fleet LCM component routing:"
kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
  psql -U postgres -d vcffleetlcmdb -c \
  "SELECT component_type, component_id, sddc_lcm_id,
     CASE WHEN sddc_lcm_id = '$NEW_SDDC_LCM_ID' THEN '✅' ELSE '❌' END as ok
   FROM component WHERE component_type IN (${TYPES_SQL}) ORDER BY component_type;"

echo "  SDDC LCM local inventory:"
kubectl exec -n vcf-sddc-lcm "$SDDC_DB_POD" -c postgres -- \
  psql -U postgres -d vcfsddclcmdb -c \
  "SELECT component_type, component_id, fqdn, version FROM component ORDER BY component_type;"
echo

# ── Done ──────────────────────────────────────────────────────────────────────
echo "======================================================================"
$DRY_RUN && echo " DRY-RUN complete — re-run without --dry-run to apply."
$DRY_RUN || echo " Done!"
echo " Target: $TARGET_FQDN  (ID: $NEW_SDDC_LCM_ID)"
echo
echo " Next steps:"
echo "  1. Restart Fleet Build Service to clear cache:"
echo "     kubectl -n vcf-fleet-lcm rollout restart deployment vcf-fleet-build-service-fleetbuild"
echo "  2. Verify support bundle generation works for VIDB"
echo "======================================================================"
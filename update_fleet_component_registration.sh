#!/bin/bash
# =============================================================================
# DR Fix: Move Fleet Component Registrations from SFO to LAX
# =============================================================================
#
# After a DR failover, Fleet LCM and SDDC LCM databases still associate
# fleet-scoped components (VIDB, Fleet LCM, Fleet Depot, Salt RaaS, OPS_LOGS)
# with the old SFO SDDC LCM instance. This script fixes that.
#
# Prerequisites:
#   - kubectl access to the LAX VMSP cluster
#   - KUBECONFIG set to the LAX cluster kubeconfig
#
# Usage:
#   export KUBECONFIG=/path/to/lax-cluster.kubeconfig
#   ./fix_dr_component_registration.sh
# =============================================================================

set -euo pipefail

# --- Configuration ---
# Old (SFO) SDDC LCM ID
OLD_SDDC_LCM_ID="218b2097-cd6b-4f0f-a480-839e770a5306"

# New (LAX) SDDC LCM ID
NEW_SDDC_LCM_ID="7a07f2c3-be5b-420a-8ce3-64b20f4ec52a"

# Platform FQDN (used to query VMSP for component IDs)
PLATFORM_FQDN="lax-sr01.lax.rainpole.io"

# Component types that are fleet-scoped and need to move
FLEET_COMPONENT_TYPES="'VIDB','SALT_RAAS','VCF_FLEET_LCM','VCF_FLEET_DEPOT','OPS_LOGS'"

# VMSP Component IDs and metadata for SDDC LCM registration
# Format: COMPONENT_TYPE|VMSP_COMPONENT_ID|FQDN|VERSION
COMPONENTS="VIDB|4038c5bf-f77d-4c54-9739-12bc6e7825e1|flt-idb01.rainpole.io|9.1.0.0.25368698
VCF_FLEET_LCM|1769b822-e28e-455a-bc28-e2711a78d13c|flt-fc01.rainpole.io|9.1.0.0.25371109
VCF_FLEET_DEPOT|cb06b1c3-15ca-42f3-9512-2527804a55cf|flt-fc01.rainpole.io|9.1.0.0.25371105
SALT_RAAS|31ec7008-a780-4776-9078-31e7086bae6e|flt-fc01.rainpole.io|9.1.0.0.25346036
OPS_LOGS|03bfbde3-d58d-475a-a7ab-80f81e0e6c06|flt-logs01.rainpole.io|9.1.0.0.25346055"

# --- Helper: Find primary DB pod ---
find_primary_pod() {
  local namespace=$1
  local pod_prefix=$2
  for pod in ${pod_prefix}-0 ${pod_prefix}-1 ${pod_prefix}-2; do
    if kubectl exec -n "$namespace" "$pod" -c postgres -- \
      psql -U postgres -t -c "SELECT pg_is_in_recovery();" 2>/dev/null | grep -q f; then
      echo "$pod"
      return
    fi
  done
  echo "ERROR: Could not find primary DB pod for $pod_prefix" >&2
  exit 1
}

echo "=== DR Component Registration Fix ==="
echo "Moving fleet-scoped components from SFO ($OLD_SDDC_LCM_ID) to LAX ($NEW_SDDC_LCM_ID)"
echo

# --- Step 1: Find primary DB pods ---
echo "Step 1: Finding primary DB pods..."
FLEET_DB_POD=$(find_primary_pod "vcf-fleet-lcm" "vcf-fleet-lcm-db")
SDDC_DB_POD=$(find_primary_pod "vcf-sddc-lcm" "vcf-sddc-lcm-db")
echo "  Fleet LCM primary DB: $FLEET_DB_POD"
echo "  SDDC LCM primary DB:  $SDDC_DB_POD"
echo

# --- Step 2: Show current state ---
echo "Step 2: Current Fleet LCM components pointing to SFO..."
kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
  psql -U postgres -d vcffleetlcmdb -c \
  "SELECT component_type, fqdn, sddc_lcm_id FROM component WHERE sddc_lcm_id = '$OLD_SDDC_LCM_ID' AND component_type IN ($FLEET_COMPONENT_TYPES);"
echo

# --- Step 3: Fix Fleet LCM DB ---
echo "Step 3: Updating Fleet LCM DB - moving fleet-scoped components to LAX SDDC LCM..."
kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
  psql -U postgres -d vcffleetlcmdb -c \
  "UPDATE component SET sddc_lcm_id = '$NEW_SDDC_LCM_ID' WHERE sddc_lcm_id = '$OLD_SDDC_LCM_ID' AND component_type IN ($FLEET_COMPONENT_TYPES);"
echo

# --- Step 4: Fix SDDC LCM DB ---
echo "Step 4: Registering fleet-scoped components in LAX SDDC LCM DB..."

echo "$COMPONENTS" | while IFS='|' read -r comp_type comp_id fqdn version; do
  echo "  Registering $comp_type ($fqdn)..."
  kubectl exec -n vcf-sddc-lcm "$SDDC_DB_POD" -c postgres -- \
    psql -U postgres -d vcfsddclcmdb -c \
    "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, version) SELECT gen_random_uuid(), '$comp_id', '$comp_type', 'VSP', '$fqdn', '$version' WHERE NOT EXISTS (SELECT 1 FROM component WHERE component_id = '$comp_id');"
done
echo

# --- Step 5: Verify ---
echo "Step 5: Verifying changes..."
echo
echo "  Fleet LCM - Components now pointing to LAX:"
kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
  psql -U postgres -d vcffleetlcmdb -c \
  "SELECT component_type, fqdn, sddc_lcm_id FROM component WHERE sddc_lcm_id = '$NEW_SDDC_LCM_ID';"
echo
echo "  SDDC LCM - All registered components:"
kubectl exec -n vcf-sddc-lcm "$SDDC_DB_POD" -c postgres -- \
  psql -U postgres -d vcfsddclcmdb -c \
  "SELECT component_type, fqdn, component_id FROM component;"
echo

echo "=== Done! ==="
echo "Fleet-scoped components have been moved to LAX SDDC LCM."
echo "SDDC LCM will refresh component data from VMSP within 15 minutes."
echo "You may need to restart Fleet LCM build service to clear stuck tasks:"
echo "  kubectl -n vcf-fleet-lcm rollout restart deployment vcf-fleet-build-service-fleetbuild"

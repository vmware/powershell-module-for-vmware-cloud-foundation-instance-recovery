#!/bin/bash
# =============================================================================
# DR Fix: Move Fleet Component Registrations (V2.4)
# =============================================================================
#
# Updates BOTH Fleet LCM and SDDC LCM databases when moving FLEET-SCOPED
# components to a new VCF instance after DR/migration.
#
# Scope: fleet-scoped components only (see FLEET_COMPONENT_TYPES below).
# VCFA registration/remediation (the VCFA component AND its consumption VSP
# cluster) has moved to a dedicated script so all VCFA work lives in one place:
#     repair_vcfa_consumption_cluster.sh
#
# What this script does:
#   1. Fleet LCM DB: Re-points component sddc_lcm_id to target SDDC LCM
#   2. Fleet LCM DB: Optionally sets target SDDC LCM as primary
#   3. SDDC LCM DB:  Ensures fleet components exist in local component inventory
#   4. OPS / OPS_NETWORKS (Steps 5b/5c): Interactively re-homes these
#      instance-scoped components from the source SDDC LCM to the target,
#      same INSERT-then-DELETE pattern as the fleet-scoped components above.
#      Each asks for confirmation before writing (skipped under --dry-run).
#
# Prerequisites:
#   - KUBECONFIG set before running, pointing to the TARGET DR cluster
#     (must have the vcf-fleet-lcm and vcf-sddc-lcm namespaces)
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
      echo "Note: OPS and OPS_NETWORKS (Steps 5b/5c) are instance-scoped and moved"
      echo "      interactively — each prompts for confirmation before writing"
      echo "      (skipped under --dry-run, which only shows what would happen)."
      echo ""
      echo "Environment:"
      echo "  KUBECONFIG               (required) Must be set before running and must point to"
      echo "                           the TARGET DR cluster (vcf-fleet-lcm + vcf-sddc-lcm"
      echo "                           namespaces). Used for all kubectl access."
      echo ""
      echo "Examples:"
      echo "  export KUBECONFIG=<target-DR-cluster-kubeconfig>"
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

# component.id is UUIDv7 app-side (glcm's @UuidV7 / UuidUtils.generateUuidv7()),
# and ordering relies on it (FailedImportService sorts by Component::getId). Since
# gen_random_uuid() only produces UUIDv4, build a v7 UUID in pure SQL instead: take
# gen_random_uuid()'s random bytes and overlay a ms timestamp + version/variant
# bits per RFC 9562. Uses set_byte()/get_byte() (whole-byte, unambiguous) rather
# than set_bit()/get_bit(), which number bits LSB-first within each byte and
# silently target the wrong bit if you assume RFC 9562's MSB-first numbering.
readonly UUIDV7_SQL="(WITH src AS (
  SELECT overlay(
           uuid_send(gen_random_uuid())
           placing substring(int8send(floor(extract(epoch from clock_timestamp()) * 1000)::bigint) from 3)
           from 1 for 6
         ) AS b
)
SELECT encode(
  set_byte(
    set_byte(b, 6, (get_byte(b, 6) & 15) | 112),
    8, (get_byte(b, 8) & 63) | 128
  ),
  'hex')::uuid
FROM src)"

# Maps Component CR label (lowercase-hyphenated) to DB component_type.
# Implemented as a function rather than an associative array for bash 3.2
# compatibility (macOS ships with bash 3.2 which lacks declare -A).
cr_type_to_db_type() {
  case "$1" in
    vidb)            echo "VIDB" ;;
    salt-raas)       echo "SALT_RAAS" ;;
    vcf-fleet-lcm)   echo "VCF_FLEET_LCM" ;;
    vcf-fleet-depot) echo "VCF_FLEET_DEPOT" ;;
    ops-logs)        echo "OPS_LOGS" ;;
    *)               echo "" ;;
  esac
}

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

# Moves a single instance-scoped component (OPS, OPS_NETWORKS) from its
# source SDDC LCM to the target, mirroring the fleet-component INSERT-then-
# DELETE pattern in Step 5 above. Unlike Step 5, this is gated behind an
# interactive confirmation since these components aren't necessarily meant
# to always follow the fleet-scoped set.
#   $1 = component_type (as stored in the DB, e.g. OPS)
#   $2 = display name for the confirmation prompt (e.g. "Ops")
#   $3 = step label (e.g. "Step 5b")
move_instance_scoped_component() {
  local comp_type=$1 display_name=$2 step_label=$3
  echo "${step_label}: ${comp_type} component registration move..."

  local COUNT
  COUNT=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT COUNT(DISTINCT component_id) FROM component WHERE component_type = '${comp_type}';")

  if [[ "${COUNT:-0}" -eq 0 ]]; then
    echo "  No $comp_type component found in Fleet LCM DB — skipping."
    echo
    return 0
  elif [[ "$COUNT" -gt 1 ]]; then
    echo "  ⚠  Found $COUNT distinct $comp_type component_ids — expected exactly 1."
    echo "     Refusing to auto-move; please handle manually."
    echo
    return 0
  fi

  # Order by (sddc_lcm_id = target) DESC so that, if this component_id already
  # has more than one row (e.g. leftover from an earlier partial/looped DR
  # run), a row already at the target sddc_lcm_id — most likely to reflect
  # current self-registered state — wins over an arbitrary/stale one. Without
  # this, DISTINCT ON with only component_id in ORDER BY picks an unspecified
  # row among duplicates, which could propagate stale fqdn/version.
  local ROW CID FQDN VER DEPLOY SIZE FLEET_ID
  ROW=$(psql_rows "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT DISTINCT ON (component_id) component_id, fqdn, version, deployment_type, size, id
     FROM component WHERE component_type = '${comp_type}'
     ORDER BY component_id, (sddc_lcm_id = '${NEW_SDDC_LCM_ID}') DESC LIMIT 1;")
  IFS='|' read -r CID FQDN VER DEPLOY SIZE FLEET_ID <<< "$ROW"

  local TARGET_ROWS STALE_ROWS
  TARGET_ROWS=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT COUNT(*) FROM component WHERE component_id = '${CID}' AND sddc_lcm_id = '${NEW_SDDC_LCM_ID}';")
  STALE_ROWS=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT COUNT(*) FROM component WHERE component_id = '${CID}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}';")

  if [[ "${TARGET_ROWS:-0}" -ge 1 && "${STALE_ROWS:-0}" -eq 0 ]]; then
    echo "  ✅ $comp_type ($CID) already registered to target only — nothing to do."
    echo
    return 0
  fi

  local SRC_SDDC SRC_FQDN TARGET_VSP_FQDN
  SRC_SDDC=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT sddc_lcm_id FROM component WHERE component_id = '${CID}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}' LIMIT 1;")
  SRC_FQDN=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT fqdn FROM sddc_lcm WHERE id = '${SRC_SDDC}' LIMIT 1;")
  # The VSP component row co-located with the target SDDC LCM is the target's
  # "VCF services runtime" — shown in the prompt so it's clear which cluster
  # this component is being mapped to, not just which SDDC LCM.
  TARGET_VSP_FQDN=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT fqdn FROM component WHERE component_type = 'VSP' AND sddc_lcm_id = '${NEW_SDDC_LCM_ID}' LIMIT 1;")

  echo "  $comp_type component found in Fleet LCM DB:"
  echo "     component_id            : $CID"
  echo "     fqdn                    : $FQDN"
  echo "     version                 : $VER"
  echo "     size                    : $SIZE"
  echo "     source SDDC LCM (from)  : ${SRC_SDDC:-<none>}  (${SRC_FQDN:-unknown})"
  echo "     target SDDC LCM (to)    : $NEW_SDDC_LCM_ID  ($TARGET_FQDN)"
  echo
  echo "  About to map \"$display_name\" to this target cluster's VCF services"
  echo "  runtime (${TARGET_VSP_FQDN:-unknown})."
  echo

  local PROCEED=false
  if $DRY_RUN; then
    echo "  [DRY-RUN] Confirmation skipped; showing intended changes only."
    PROCEED=true
  else
    read -r -p "  Move $comp_type registration from source → target? [y/N] " ANS || ANS=""
    case "$ANS" in
      [yY]|[yY][eE][sS]) PROCEED=true ;;
      *) echo "  ⏭  Skipped $comp_type move (not confirmed)." ;;
    esac
  fi

  if $PROCEED; then
    DEPLOY=${DEPLOY:-VSP}
    SIZE=${SIZE:-medium}

    local EXISTS
    EXISTS=$(psql_one "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
      "SELECT COUNT(*) FROM component WHERE component_id = '${CID}';")
    if [[ "${EXISTS:-0}" -ge 1 ]]; then
      run_psql "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
        "UPDATE component SET fqdn = '${FQDN}', version = '${VER}' WHERE component_id = '${CID}';" \
        "SDDC LCM: UPDATE $comp_type (refreshing metadata)"
    else
      run_psql "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
        "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version)
         VALUES ('${FLEET_ID}', '${CID}', '${comp_type}', '${DEPLOY}', '${FQDN}', '${SIZE}', '${VER}');" \
        "SDDC LCM: INSERT $comp_type ($CID)"
    fi

    if [[ "${TARGET_ROWS:-0}" -ge 1 ]]; then
      echo "    OK   $comp_type — target row already exists"
    else
      # Use the already-resolved $comp_type/$DEPLOY/$FQDN/$SIZE/$VER rather
      # than re-querying "FROM component WHERE component_id = ... LIMIT 1"
      # here: with more than one existing row for this component_id, a bare
      # LIMIT 1 with no ORDER BY could pick a different (and possibly stale)
      # row than the one already chosen above, propagating stale metadata.
      run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
        "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version, sddc_lcm_id)
         VALUES (${UUIDV7_SQL}, '${CID}', '${comp_type}', '${DEPLOY}', '${FQDN}', '${SIZE}', '${VER}', '${NEW_SDDC_LCM_ID}');" \
        "Fleet LCM: INSERT $comp_type row for target SDDC LCM"
    fi
    # Re-point node rows (VM/appliance inventory — OPS/OPS_NETWORKS are
    # OVA-deployed and carry MASTER/REPLICA/DATA/collector node records) off
    # the stale component row before deleting it. Same fk_node_component
    # blocker as fk_component_config_component below.
    run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "UPDATE node SET component_id = (
         SELECT id FROM component WHERE component_id = '${CID}' AND sddc_lcm_id = '${NEW_SDDC_LCM_ID}' LIMIT 1
       )
       WHERE component_id IN (
         SELECT id FROM component
         WHERE component_id = '${CID}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}'
       );" \
      "Fleet LCM: RE-POINT $comp_type node rows to target component row"
    # Re-point component_config rows onto the target component row instead of
    # deleting them — the target row above is a bare INSERT ... SELECT of
    # component's own columns and never carries config of its own, so a plain
    # delete here would leave $comp_type registered but with its configuration
    # entirely gone. Only re-point a (type) the target doesn't already have,
    # so config genuinely already on the target row is never clobbered.
    run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "UPDATE component_config
       SET component_id = (
         SELECT id FROM component WHERE component_id = '${CID}' AND sddc_lcm_id = '${NEW_SDDC_LCM_ID}' LIMIT 1
       )
       WHERE component_id IN (
         SELECT id FROM component
         WHERE component_id = '${CID}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}'
       )
       AND type NOT IN (
         SELECT type FROM component_config WHERE component_id = (
           SELECT id FROM component WHERE component_id = '${CID}' AND sddc_lcm_id = '${NEW_SDDC_LCM_ID}' LIMIT 1
         )
       );" \
      "Fleet LCM: RE-POINT $comp_type component_config to target component row"
    # Anything left is stale config whose type already exists on the target
    # row (couldn't be re-pointed without a duplicate) — delete just that
    # leftover so fk_component_config_component doesn't block the row delete.
    run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "DELETE FROM component_config
       WHERE component_id IN (
         SELECT id FROM component
         WHERE component_id = '${CID}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}'
       );" \
      "Fleet LCM: DELETE $comp_type leftover conflicting component_config rows"
    run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "DELETE FROM component WHERE component_id = '${CID}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}';" \
      "Fleet LCM: DELETE $comp_type stale rows (non-target SDDC LCMs)"

    if ! $DRY_RUN; then
      echo "  $comp_type after move:"
      echo "    Fleet LCM DB:"
      kubectl exec -n vcf-fleet-lcm "$FLEET_DB_POD" -c postgres -- \
        psql -U postgres -d vcffleetlcmdb -c \
        "SELECT component_type, component_id, fqdn, sddc_lcm_id FROM component WHERE component_id = '${CID}';"
      echo "    SDDC LCM DB:"
      kubectl exec -n vcf-sddc-lcm "$SDDC_DB_POD" -c postgres -- \
        psql -U postgres -d vcfsddclcmdb -c \
        "SELECT component_type, component_id, fqdn, version FROM component WHERE component_id = '${CID}';"
    fi
  fi
  echo
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo "======================================================================"
echo " DR Fix: Fleet Component Registration (V2.3)"
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
# DISTINCT ON (component_id) collapses the multiple rows that exist per component
# (one per sddc_lcm_id after failover/failback) into a single canonical row so
# each component is processed exactly once in Steps 4 and 5. Ordered by
# (sddc_lcm_id = target) DESC as a tiebreaker: with only component_id in
# ORDER BY, Postgres picks an unspecified row among duplicates, which could
# propagate a stale row's fqdn/version into Steps 4/5 instead of the row
# already reflecting the target (or most relevant) registration.
echo "  Checking Fleet LCM database..."
DB_COMPONENTS=$(psql_rows "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
  "SELECT DISTINCT ON (component_id) component_type, component_id, fqdn, version, deployment_type, size
   FROM component
   WHERE component_type IN (${TYPES_SQL})
   ORDER BY component_id, (sddc_lcm_id = '${NEW_SDDC_LCM_ID}') DESC;")

# If DB query returned nothing but we have CRs, build DB_COMPONENTS from CRs
if [[ -z "$DB_COMPONENTS" && -n "$KUBECTL_COMPONENTS" ]]; then
  echo "  Fleet LCM DB has no fleet components yet; using Component CRs as source"
  while IFS=$'\t' read -r cr_type cr_id; do
    db_type=$(cr_type_to_db_type "$cr_type")
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

# ── Step 4: Ensure fleet components exist in SDDC LCM local inventory ─────────
# Must happen BEFORE Fleet LCM routing is updated so that ResolveComponentAction
# never sees the component pointing to the target before the target can resolve it.
echo "Step 4: Ensuring fleet components exist in SDDC LCM local inventory..."

echo "$DB_COMPONENTS" | while IFS='|' read -r comp_type comp_id comp_fqdn comp_version comp_deploy comp_size; do
  EXISTS=$(psql_one "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
    "SELECT COUNT(*) FROM component WHERE component_id = '${comp_id}';")

  if [[ "$EXISTS" -ge "1" ]]; then
    run_psql "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
      "UPDATE component SET fqdn = '${comp_fqdn}', version = '${comp_version}' WHERE component_id = '${comp_id}';" \
      "SDDC LCM: UPDATE $comp_type (refreshing metadata)"
    continue
  fi

  # Use Fleet LCM's internal row ID as primary key for consistency. Tie-broken
  # toward the target sddc_lcm_id's row so that, if this component_id already
  # has more than one Fleet LCM row, we mirror the one that will actually
  # survive Step 5 rather than an arbitrary (possibly soon-to-be-deleted) one.
  FLEET_INTERNAL_ID=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT id FROM component WHERE component_id = '${comp_id}'
     ORDER BY (sddc_lcm_id = '${NEW_SDDC_LCM_ID}') DESC LIMIT 1;")

  comp_deploy=${comp_deploy:-VSP}
  comp_size=${comp_size:-small}

  run_psql "vcf-sddc-lcm" "$SDDC_DB_POD" "vcfsddclcmdb" \
    "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version)
     VALUES ('${FLEET_INTERNAL_ID}', '${comp_id}', '${comp_type}', '${comp_deploy}', '${comp_fqdn}', '${comp_size}', '${comp_version}');" \
    "SDDC LCM: INSERT $comp_type ($comp_id)"
done
echo

# ── Step 5: Update Fleet LCM routing ─────────────────────────────────────────
# SDDC LCM inventory is ready — now safe to reroute Fleet LCM to the target.
# Uses INSERT-then-DELETE rather than UPDATE to avoid leaving stale rows that
# cause duplicates when PushCapabilities later re-registers from the old SDDC LCM.
echo "Step 5: Updating Fleet LCM DB — re-pointing components to target SDDC LCM..."

echo "$DB_COMPONENTS" | while IFS='|' read -r comp_type comp_id comp_fqdn comp_version comp_deploy comp_size; do
  # Ensure a row exists for (component_id, target_sddc_lcm_id)
  TARGET_EXISTS=$(psql_one "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "SELECT COUNT(*) FROM component WHERE component_id = '${comp_id}' AND sddc_lcm_id = '${NEW_SDDC_LCM_ID}';")

  if [[ "$TARGET_EXISTS" -ge "1" ]]; then
    echo "  OK   $comp_type — target row already exists"
  else
    comp_deploy=${comp_deploy:-VSP}
    comp_size=${comp_size:-small}
    # Use the already-resolved $comp_type/$comp_deploy/$comp_fqdn/$comp_size/
    # $comp_version (from Step 3's DISTINCT ON query, now tie-broken toward
    # the target sddc_lcm_id) rather than re-querying "FROM component WHERE
    # component_id = ... LIMIT 1" here: with more than one existing row for
    # this component_id, a bare LIMIT 1 with no ORDER BY could pick a
    # different (and possibly stale) row, propagating stale metadata.
    run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
      "INSERT INTO component (id, component_id, component_type, deployment_type, fqdn, size, version, sddc_lcm_id)
       VALUES (${UUIDV7_SQL}, '${comp_id}', '${comp_type}', '${comp_deploy}', '${comp_fqdn}', '${comp_size}', '${comp_version}', '${NEW_SDDC_LCM_ID}');" \
      "Fleet LCM: INSERT $comp_type row for target SDDC LCM"
  fi

  # Re-point node rows (VM/appliance inventory for OVA-deployed components,
  # e.g. OPS) off the stale component row before deleting it. fk_node_component
  # is the same kind of blocker as fk_component_config_component below; this is
  # a no-op for VSP-deployment types, which never have node rows.
  run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "UPDATE node SET component_id = (
       SELECT id FROM component WHERE component_id = '${comp_id}' AND sddc_lcm_id = '${NEW_SDDC_LCM_ID}' LIMIT 1
     )
     WHERE component_id IN (
       SELECT id FROM component
       WHERE component_id = '${comp_id}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}'
     );" \
    "Fleet LCM: RE-POINT $comp_type node rows to target component row"
  # Re-point component_config rows onto the target component row (the target
  # row is a bare INSERT ... SELECT of component's own columns above and never
  # carries config of its own) rather than just deleting them — otherwise the
  # component survives the move with an empty component_config and loses its
  # configuration entirely. Only re-point a (type) that the target doesn't
  # already have, so any config genuinely already present on the target row
  # (e.g. from an earlier partial run) is never clobbered by stale data.
  run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "UPDATE component_config
     SET component_id = (
       SELECT id FROM component WHERE component_id = '${comp_id}' AND sddc_lcm_id = '${NEW_SDDC_LCM_ID}' LIMIT 1
     )
     WHERE component_id IN (
       SELECT id FROM component
       WHERE component_id = '${comp_id}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}'
     )
     AND type NOT IN (
       SELECT type FROM component_config WHERE component_id = (
         SELECT id FROM component WHERE component_id = '${comp_id}' AND sddc_lcm_id = '${NEW_SDDC_LCM_ID}' LIMIT 1
       )
     );" \
    "Fleet LCM: RE-POINT $comp_type component_config to target component row"
  # Anything left at this point is stale config whose type already exists on
  # the target row (couldn't be re-pointed without a duplicate) — delete just
  # that leftover so the FK constraint (fk_component_config_component) doesn't
  # block deleting the stale component row below.
  run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "DELETE FROM component_config
     WHERE component_id IN (
       SELECT id FROM component
       WHERE component_id = '${comp_id}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}'
     );" \
    "Fleet LCM: DELETE $comp_type leftover conflicting component_config rows"
  run_psql "vcf-fleet-lcm" "$FLEET_DB_POD" "vcffleetlcmdb" \
    "DELETE FROM component WHERE component_id = '${comp_id}' AND sddc_lcm_id != '${NEW_SDDC_LCM_ID}';" \
    "Fleet LCM: DELETE $comp_type stale rows (non-target SDDC LCMs)"
done
echo

# ── Step 5b/5c: Move OPS / OPS_NETWORKS registrations (interactive) ──────────
# OPS and OPS_NETWORKS are instance-scoped components (NOT in
# FLEET_COMPONENT_TYPES). After DR they may still be registered under the
# SOURCE instance's SDDC LCM and need to be re-homed to the target. Gated
# behind confirmation since, unlike the fleet-scoped set, moving these isn't
# always desired.
move_instance_scoped_component "OPS" "Ops" "Step 5b"
move_instance_scoped_component "OPS_NETWORKS" "Ops for networks" "Step 5c"

# ── VCFA registration/remediation ────────────────────────────────────────────
# VCFA (the instance-scoped component) and its consumption VSP cluster are handled
# by a dedicated script so all VCFA work lives in one place:
#     repair_vcfa_consumption_cluster.sh
# This script now covers ONLY the fleet-scoped components listed in
# FLEET_COMPONENT_TYPES above.

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
echo "  (Each fleet component should have exactly one row pointing to the target)"
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
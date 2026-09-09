# Plan step condition reference

Reference for anyone hand-authoring `"condition"` entries in a recovery plan JSON file
(`plans\ibr\*.json`, `plans\fdr\*.json`). Implemented in `VCFRecoveryOrchestratorUI.ps1`
(`Test-StepCondition`, `Test-ConditionOperator`, `Resolve-ConditionDataPath`,
`Test-DataPathCondition`, `Test-StepStatusGate`, `Get-RecoveryPlanSteps`).

## Where `condition` fits in a step

```json
{
  "description": "...",
  "commandLine": "...",
  "id": "...",
  "condition": [ ... ],
  "threadId": "",
  "interactive": false
}
```

`condition` is an array. **Every entry must be true** for the step to run (empty array/absent =
always runs). Every entry must be one of the three typed objects below — there is no raw-
PowerShell-expression form; that was removed deliberately, and every condition in the shipped plans
has been migrated to one of these three kinds.

`id` is optional — only add it to a step some other step's `stepStatus` condition needs to
reference. No uniqueness is enforced across a plan file; a duplicate `id` is last-write-wins in the
runtime status ledger.

## Condition entry forms

| Form | Shape | Notes |
|---|---|---|
| `variable` | `{ "type": "variable", "name": "...", "operator": "...", "value": ... }` | Looks up an operator-typed-in value from the Variables tab/answers file. |
| `dataPath` | `{ "type": "dataPath", "path": "...", "operator": "...", "value": ... }` | Looks up a live fact from the currently selected domain/cluster — see [Data model](#data-model-dataPath-context-by-recovery-scope) below. |
| `stepStatus` | `{ "type": "stepStatus", "stepId": "...", "operator": "...", "value": "..." }` | Gates on whether another step (by its `id`) already ran and how it went. **Only ever gates execution — never hides a step from the Steps list.** |

A step's `condition` array can freely mix any of the above forms in one list — all must pass. There
is no `any`/`all`/`not` combinator across entries — the array is always an implicit AND. There is
currently no way to express OR logic directly in a condition; if you need it, that's a gap to raise,
not something to work around with a raw expression.

## Operators

Shared by all three condition kinds.

| Operator | Meaning | `value` shape |
|---|---|---|
| `eq` | Actual equals value (string comparison) | scalar |
| `ne` | Actual does not equal value | scalar |
| `in` | Actual is one of value | array |
| `notIn` | Actual is not one of value | array |
| `exists` | Actual is non-null/non-empty | omit or `null` |
| `notExists` | Actual is null/empty | omit or `null` |
| `match` | Actual matches value as a regex | regex string |

An unrecognized operator name fails open (treated as `true`) — see
[Fail-open vs. fail-closed](#fail-open-vs-fail-closed) below.

## `variable` — operator-typed-in values

```json
{ "type": "variable", "name": "locationtype", "operator": "eq", "value": "SFTP" }
```

Looks up `$Variables['locationtype']` — the same dict the Variables tab builds from an answers
file/manual edits. There is no fixed catalog of names: whatever variable names actually appear
across a plan's own `commandLine`s (and typed conditions' `name`/`path` leaf) is what shows up as a
promptable row on the Variables tab for that plan. To find out what's available for a given plan,
either look at the `$name`-style tokens already used in that plan file's `commandLine`s, or load the
plan in the app and read the Variables tab it builds.

## `dataPath` — live extracted-data facts

```json
{ "type": "dataPath", "path": "selectedCluster.isStretched", "operator": "eq", "value": "t" }
```

`path` is dot-separated, walked against `$global:conditionDataContext` — see the per-scope table
below for what's actually populated there. Resolution order:
1. If the path's **last segment name** is present with a non-blank value in the operator's answers
   dict (i.e. someone typed/overrode it on the Variables tab), that value wins.
2. Otherwise, resolves live from `$global:conditionDataContext`.

This is why `isStretched`/`primaryDatastoreType` still show up as ordinary, pre-filled, *editable*
Variables-tab rows — typing a real value there still overrides the extracted-data value, exactly as
before this mechanism existed.

### Data model (`dataPath` context) by Recovery Scope

| IBR Recovery Scope | `selectedDomain` | `selectedCluster` |
|---|---|---|
| Management Domain Recovery | raw MANAGEMENT domain object from extracted data (see below) | that domain's **default** cluster (`isDefault == 't'`), normalized (see below) |
| Workload Domain Recovery | raw selected VI domain object from extracted data | that domain's **default** cluster (`isDefault == 't'`), normalized |
| Additional Cluster Recovery | `$null` | the selected additional cluster, normalized (`isDefault` is always `'f'` here) |
| Fleet Component Recovery | `$null` | `$null` |
| FDR (Failover) | `$null` | `$null` |

Before anything is selected within a scope that supports a selection, both are `$null` too — any
`dataPath` referencing them then resolves to `$null`, which compares as a normal (not fail-open)
`false`.

`selectedCluster` fields (same normalized camelCase shape regardless of which scope populated it):

| Field | Example |
|---|---|
| `selectedCluster.name` | `"sfo-m01-cl01"` |
| `selectedCluster.isDefault` | `"t"` / `"f"` |
| `selectedCluster.isStretched` | `"t"` / `"f"` |
| `selectedCluster.primaryDatastoreType` | `"VSAN"` / `"VSAN_ESA"` / ... |
| `selectedCluster.domainName` | `"sfo-m01"` |

`selectedDomain` is the **raw, un-normalized** domain object straight from
`extracted-sddc-data.json` (only populated for the two domain-based scopes) — known fields include
`domainName`, `domainType`, `vsphereClusterDetails` (array of raw cluster objects, each with its own
`name`/`isDefault`/`isStretched`/`primaryDatastoreType`/... in the extractor's own camelCase). Prefer
`selectedCluster` for anything about "the cluster this run is targeting" — it's already resolved to
the right one for you and normalized; reach into `selectedDomain` only for domain-level facts (e.g.
`selectedDomain.domainType`) or to inspect a cluster *other than* the default one.

## `stepStatus` — depending on another step's outcome

```json
{ "type": "stepStatus", "stepId": "deploy-nsx-edges", "operator": "eq", "value": "Success" }
```

Give the step being depended on an `"id"`:
```json
{ "id": "deploy-nsx-edges", "commandLine": "Invoke-NSXEdgeClusterRecoverySelective ...", ... }
```

`value` is one of: `Success`, `Failed`, `Skipped`, `NotRun` (a step id that hasn't run yet this
selection reads as `NotRun`). Checked against `$global:stepRunStatus`, stamped as steps actually
run/complete.

**Important:** `stepStatus` is evaluated in exactly one place — right before a step would actually
execute (`Invoke-Step`'s pre-flight gate) — never when the Steps list itself is built or refreshed.
A step gated on `stepStatus` always shows up in the list with a normal Run button, even before its
dependency has ever run; clicking Run on it (manually, or via Run All reaching it) is what actually
evaluates the gate. If the gate fails, the button turns gray/"Skipped" immediately (nothing is sent
to the console) and, in a chain, the run continues to the next step as if this one succeeded.

The status ledger resets automatically on every fresh domain/cluster (re)selection — including
switching directly from one domain/cluster to another, not just to "nothing selected" — since a step
`id` is only unique within one plan file and the same plan can legitimately run again for a
different target in the same session.

## Fail-open vs. fail-closed

These look similar but are not the same thing — worth knowing which one you're looking at when a
condition doesn't do what you expect:

- **Fail-open (silently treated as `true`)**: a condition entry that isn't a recognized typed
  object at all (e.g. a malformed entry, an unrecognized `type`, an unrecognized `operator`), or one
  that throws during evaluation. The reasoning: hiding a real recovery step because of a condition-
  authoring bug is worse than showing one that turns out to be unnecessary — but it also means a
  broken condition won't error loudly, it will just always show/run.
- **Fail-closed (a real, non-thrown `false`)**: a `variable`/`dataPath` whose value genuinely isn't
  known yet (nothing selected, nothing typed in) resolves to `$null`, and comparing `$null` against
  an expected value is a legitimate `false`, not an error. This is a normal, expected state, not a
  bug.

## Worked examples

```json
{ "condition": [ { "type": "dataPath", "path": "selectedCluster.isStretched", "operator": "eq", "value": "t" } ] }
```
Run only if the targeted cluster is stretched.

```json
{ "condition": [ { "type": "dataPath", "path": "selectedCluster.primaryDatastoreType", "operator": "in", "value": ["VSAN", "VSAN_ESA"] } ] }
```
Run for either vSAN flavor.

```json
{ "condition": [ { "type": "variable", "name": "locationtype", "operator": "eq", "value": "SFTP" } ] }
```
Run only if the operator chose an SFTP backup location.

```json
{ "id": "redeploy-nsx-edges", "commandLine": "Invoke-NSXEdgeClusterRecoverySelective ... -monitor", ... }
```
```json
{ "condition": [ { "type": "stepStatus", "stepId": "redeploy-nsx-edges", "operator": "eq", "value": "Success" } ] }
```
Run a later step only if the NSX edge redeploy actually succeeded.

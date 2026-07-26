# Adaptive-runtime experiment-control hardening reproductions

Date: 2026-07-25  
Reviewed source commit: `c7076b191f6f0b3f3d3ee94b477746fc286f4144`  
Scope: correctness-only reproduction before repair

## Safety boundary

No benchmark, performance campaign, ProtocolLab campaign, workload matrix,
transform, CI action, policy activation, axis migration, or push was performed.
The primary dirty worktree and the staged runtime-evidence incident worktree
were not modified.

## Reproduced defects

| Defect | Reproduction | Observed baseline |
| --- | --- | --- |
| Duplicate behavior-derivation authority | Inspect `Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1` and compare its executable `$behaviorByEvent` table with the versioned effective-behavior catalog's `mechanism_events`. | The validator derives from the PowerShell table; the catalog only supplies the supported behavior-ID set and version/hash check. A catalog mapping cannot become authoritative without changing PowerShell. |
| Filename-derived warnings | Copy the inactive evidence without changing its semantic content to `retained_inactive_content_stable_copy.warning.fixture.json` and expect `inactive_operation_retained`. | The warning is absent because the warning switch examines the filename. |
| Incomplete decision-to-operation reconciliation | Change an operation's `candidate_value` while retaining the linked decision candidate and expect `candidate_value_mismatch`. | The validator returns no error. |
| Incomplete epoch/classification joins | Replace the sole connection-epoch identity with a different epoch and independently duplicate a classification ID. | The validator returns neither `top_epoch_missing` nor `classification_id_duplicate`. |

## Expected-failing command

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1 -RepoRoot .
```

Expected baseline result:

```text
schemas_validated: 3
valid_fixtures: 16
warning_fixtures: 4
invalid_fixtures: 21
deterministic_materialization_and_projection_runs: 16
failures:
  candidate_value_mismatch.fixture.json: expected candidate_value_mismatch; observed no error
  classification_id_duplicate.fixture.json: expected classification_id_duplicate; observed no error
  retained_inactive_content_stable_copy.warning.fixture.json: warning_mismatch
  top_epoch_missing.fixture.json: expected top_epoch_missing; observed no error
```

This red checkpoint is intentional. The fixtures remain immutable proof inputs
for the corrective implementation and must pass only after the corresponding
catalog, warning, reconciliation, and join rules are implemented.

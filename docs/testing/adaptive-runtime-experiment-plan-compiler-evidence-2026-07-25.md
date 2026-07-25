---
title: "Adaptive Runtime Experiment-Plan Compiler Evidence - 2026-07-25"
---

# Adaptive Runtime Experiment-Plan Compiler Evidence - 2026-07-25

Status: focused compiler, fixtures, and dry-run manifest proof clean;
measurement and active behavior remain unauthorized

Trace: `REQ-QUIC-CRT-0202` through `REQ-QUIC-CRT-0205`,
`ARC-QUIC-CRT-0092`, `WI-QUIC-CRT-0093`, and `VER-QUIC-CRT-0094`

## Recovery and preservation

The primary `C:\shared\src\incursa\quic-dotnet` worktree remained on `main`,
104 commits ahead of `origin/main`, with its coherent Stage 5 ACK-profile work
preserved. It was not reset, cleaned, stashed, relabeled, or mixed into this
checkpoint.

This checkpoint used:

- linked worktree:
  `C:\shared\src\incursa\.worktrees\quic-experiment-plan-compiler-20260725`;
- branch: `codex/adaptive-runtime-plan-compiler-20260725`; and
- source checkpoint:
  `bc226c159f28172e5c4732e97290704c10e28c90`.

No build, test, campaign, or transform process was active at recovery.

## Foundation prerequisite

The preceding checkpoint was revalidated after the narrow additive schema
correction:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1 -RepositoryRoot .
```

Result:

- 8 schemas valid;
- 5 canonical documents valid;
- 12 valid foundation fixtures valid;
- 15 invalid foundation fixtures rejected with 0 code mismatches;
- unknown fields rejected;
- canonical bytes and repeated hashes identical; and
- canonical references and hashes valid.

The v1 historical policy catalog remains compatibility-only for retained
evidence. Its protected files are byte-identical to `bc226c15`:

| File | Git blob |
| --- | --- |
| `schemas/adaptive-runtime-policy-catalog-v1.schema.json` | `a1f961462767cef3fe16da957d1d118ac1d1f4fb` |
| `eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1` | `47d9fc5cf5f6a8960ff18b3d8c0583a834c335ce` |

## Schema correction

The reviewed v1 contracts were extended only where compilation required
facts that the foundation intentionally deferred:

- axis readiness, forceability, rollback and actuation status, activation and
  behavior-distinctness predicates, and capability requirements;
- source-plan fixed values, expected capabilities, history controls,
  transparent profiles, activation expectations, and order policy;
- closed compiler classifications, errors, warnings, cell counts, behavior
  classes, equivalence groups, and cell states; and
- runner, host, capability, cell-exclusion, order, output, retention, and
  result-schema provenance for dry-run manifests.

Existing foundation fixtures retain their v1 compatibility. Unknown fields
remain rejected. All authorization fields remain constrained false.

## Compiler fixture proof

Command:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentPlanCompiler.ps1 -RepositoryRoot .
```

Result:

- 7 valid or structurally valid plan fixtures;
- 5 warning or verification-classified plan fixtures;
- 12 exact warning-code proofs;
- 21 invalid plans;
- 5 invalid manifests;
- 1 invalid validation result;
- 0 mismatches or failures;
- repeated canonical validation bytes equal;
- repeated hashes equal;
- root self-hash excluded;
- set-like array order normalized;
- treatment order preserved;
- meaningful candidate changes alter hashes; and
- plan, validation, and manifest hash roles not interchangeable.

The valid plans cover batch and buffer actuation, batch and buffer isolated
counterfactuals, the send-composition interaction, feedback-loop history, and
transparent profile validation. Warning fixtures cover capability pending,
structural inactivity, unproven distinctness, actuation-preserved equivalence,
and isolated-equivalence deduplication.

The invalid corpus covers unknown and blocked axes, Stage 5 preparation-only
execution, illegal values and combinations, missing forced actuation,
unreachable activation, invalid
fixed adjacent values, isolated axis-count violations, an axis outside an
interaction family, missing feedback history, false performance comparison of
equivalent cells, plan and manifest hash mismatches, validation hash mismatch,
plan/manifest version mismatch, stale references, unknown fields, duplicate
axis references, missing predicates, prohibited controller input, both
forbidden authorizations, and unsupported experiment type.

## Send-turn equivalence

The fixture
`warning/send-verification.plan.json` produces:

- classification: `verification_only`;
- configured cells: 2;
- expected effective cells: 1;
- retained verification cells: 2; and
- warning:
  `all_configured_values_collapse_to_one_expected_behavior`.

Both configured labels resolve through the reviewed effective-behavior catalog
to
`behavior.application_send_turn_planning.legacy_priority_stable_sequence`.
Performance comparison remains false.

## Focused build and tests

The first `--no-restore` build correctly stopped because the fresh linked
worktree had no `project.assets.json`. A normal focused build restored only
the affected project graph and succeeded. The clean committed-source build
used:

```powershell
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore
```

Result: 0 warnings, 0 errors in 59.45 seconds.

Focused requirement-home tests:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release `
  --no-build `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0202|FullyQualifiedName~REQ_QUIC_CRT_0203|FullyQualifiedName~REQ_QUIC_CRT_0204|FullyQualifiedName~REQ_QUIC_CRT_0205"
```

Result: 4 passed, 0 failed, 0 skipped.

No complete Release suite or performance test ran.

## Real dry-run manifest

The manifest was created only after source commit
`2ce2d806fdaed8433e67d7f45c31ae541c374f55` was clean and the focused build
succeeded.

Artifact:
`eng/adaptive-runtime/experiment-control/proofs/adaptive-runtime-batch-actuation-dry-run-manifest-v1.json`

Proof:

| Fact | Value |
| --- | --- |
| plan SHA-256 | `928762c81b37c3a3a026223c83a5b89e0478c68bb88aa152d82c648f43d461b1` |
| validation SHA-256 | `45bd451a433fc4f130d96fec6e7ad189de8f4a33311156589e26d547c8729a0c` |
| manifest SHA-256 | `6dd5f4741f1ae9e1a4565d4e74f5095f40c093c95e9c1aebc6086d5767aef3e5` |
| binary | `tests/Incursa.Quic.Tests/bin/Release/net10.0/Incursa.Quic.Tests.dll` |
| binary SHA-256 | `0a3c167ddd9ca2eb7f7996f889aab1d08971a9206f7b9908c7829aaaaf78fead` |
| runner | `Compile-AdaptiveRuntimeExperimentPlan.ps1` |
| runner version | `1.0.0-dry-run` |
| runner SHA-256 | `d2e41d6601765cee6c41a8849e86ebaccce8ebb586f59e8f324ca9d669703346` |
| host fingerprint | `host.0080d5b929520780449ad8cd` |
| VM ID | `78848434-7C6C-4836-B04B-845540F2B138` |
| internal forced-mode capability | `available` |
| send-composition multi-axis capability | `unavailable` |
| execution order | `cell.batch_actuation.000`, `cell.batch_actuation.001` |

Validation command:

```powershell
./eng/adaptive-runtime/Test-AdaptiveRuntimeCompiledExecutionManifest.ps1 `
  -PlanPath ./tests/fixtures/adaptive-runtime-experiment-plan-compiler/valid/batch-actuation.plan.json `
  -ValidationPath ./tests/fixtures/adaptive-runtime-experiment-plan-compiler/valid/batch-actuation.validation.json `
  -ManifestPath ./eng/adaptive-runtime/experiment-control/proofs/adaptive-runtime-batch-actuation-dry-run-manifest-v1.json `
  -RepositoryRoot .
```

Result: valid with no errors. The manifest launched nothing.

## Trace validation

The following artifacts pass direct `model/model.schema.json` validation:

- `SPEC-QUIC-CRT-EXPERIMENT-CONTROL`;
- `ARC-QUIC-CRT-0092`;
- `WI-QUIC-CRT-0093`; and
- `VER-QUIC-CRT-0094`.

The repo-wide core validator remains an unrelated baseline-blocked command
from the preceding checkpoint and was not used to rewrite legacy trace
artifacts.

## Safety result

- no runtime policy mechanism changed;
- no runtime instrumentation or operation correlation changed;
- no effective-behavior materialization or analytics ran;
- no BenchmarkDotNet, performance, ProtocolLab, or large local campaign ran;
- no transform, normalization, curation, split, or ML work ran;
- no CI file or trigger changed;
- nothing was pushed;
- `active_internal` was not activated;
- production policy behavior was not activated; and
- measurement and performance acceptance remain frozen.

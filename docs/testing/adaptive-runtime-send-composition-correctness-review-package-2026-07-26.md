---
title: "Adaptive-runtime send-composition correctness review package"
---

# Adaptive-runtime send-composition correctness review package

## Recovery and isolation

The mission started from
`977ea6351df047288cd3acf06f86374b18cf08e0`. Git ancestry proved the
complete chain from `c7076b19` through `e6830c90` and `b5654591`. Work ran
only in
`C:\shared\src\incursa\.worktrees\quic-send-composition-correctness-20260726`
on `codex/adaptive-runtime-send-composition-correctness-20260726`. The dirty
primary and prior linked worktrees were not reset, cleaned, stashed, merged,
or repaired.

## Single-axis review and promotion

The historical candidate binary could not be reproduced from its recorded
path, and the harness had two expectation-shaped shortcuts: batch selected
count was prefilled and buffer applied segment count came from a caller
argument. Both were reproduced and corrected without changing policy
mechanisms. Fresh candidates were generated from committed source
`80113e613643fd1fdbed38cde42efdc5244401eb` and test binary
`fa51870fe039af36d755357458e54b68dfa9ac30fa5342f551e15976a7285751`.

Independent review results:

| Axis/value | Candidate hash | Review hash | Outcome |
| --- | --- | --- | --- |
| `application_send_batch_formation=single_eligible` | `729dcabcd2798291145c6cbfe5b700ccfa07ae97318a1778603b3ebb9adcf2bf` | `f40368b49bfdc8607d22449e7e80e6c1dda03a611da2362909907710a6d24b37` | `passed` |
| `buffer_copy_coalescing=memory_conservative` | `e7df3b17dec5497a0ed92904bf5b08202d4206796bdeeb1f2770a9b357b63362` | `da60ba782cd646f6c285ff1ef6dda877bc30c984054644f2bc501025e6c02408` | `passed` |

The original candidate documents remain immutable. The v2 family catalog
references the independent review results, not the candidate claims.

## Correctness authorization

The plan compiler accepts multiple behavior-distinct axes only when the plan
is an `interaction_screen` for `send_composition`, declares
`execution_purpose=correctness_only`, names exactly the two canonical passed
review documents, keeps the outside axis at `legacy_current`, and retains
both active and performance authorization as false.

The compiled manifest carries one strict authorization block for
`cell.send_composition.correctness.000`. Runtime configuration receives a
fixed internal token containing the exact manifest, cell, and proof hashes.
Public connection options cannot supply it. Missing, malformed, wrong-cell,
third-axis, active, and performance-authorized paths remain denied.

## Real mechanism execution

Committed runtime source `87243f471bb12b1f6f87f1ca8a3296f44af9131a`
was built into
`Incursa.Quic.Tests.dll` SHA-256
`a934a145e3231a2b5f19c40843d91947229cc65e6ac2370fa7c788c63db787c5`.
The exact validation hash was
`0ed559009f3515873b8617b4b9509cebcef2823fc5844e7b5d496f0e5b309c98`;
the compiled manifest hash was
`b7fdc2184c015c3917c30cffbf2e8faf35305cb0511c06fe51b0fe789e53d770`.

The focused harness invoked the production batch selector and evidence
builder, buffer policy, runtime evidence sink, owner token, and terminal
release observer. It emitted 11 operations and four releases covering:

| Case | Batch | Buffer |
| --- | --- | --- |
| both distinct | single legal selected prefix | lower two-source cap |
| batch distinct, buffer inactive | distinct | within cap |
| batch inactive, buffer distinct | one-write inactive | distinct |
| both inactive | one-write inactive | within cap |
| safety fallback | candidate clamped to legacy | independently retained |
| shadow | recommendation did not actuate | unchanged |
| rollback | legacy prefix restored | no stale forced state |

The established `supplies_work` relationship prevents same-operation dual
actuation when batch shortens to one selected write. “Both distinct” is
therefore truthfully cell-level across two exactly attributable operations,
not an impossible same-operation claim.

## Immutable evidence, ownership, and review

The immutable chain contains the plan, validation, manifest, run, host,
binary, workload instance, requested and effective shapes, operation
evidence, behavior and outcome materializations, correctness metrics,
artifact inventory, classifications, and projection. All joins use the full
composite operation identity.

Results:

| Evidence | Result |
| --- | --- |
| operations | 11 |
| terminal buffer releases | 4, each exactly once |
| behavior aggregates | 11 |
| outcome aggregates | 5 |
| projection SHA-256 | `3b0a5a855a530773085036b8a24e24679e233f2ab952f77d480f6d38caafd4a9` |
| interaction proof SHA-256 | `4418c76a42d80e0495770d93c5fa037d77d5bed620b4847c49423dc1d88ca12d` |
| independent review SHA-256 | `53adef1ddafbc28cd5c87e2795f69973c42b91f33e5a0b4344bb8ce1461458e6` |
| independent review | `passed` |

The reviewer re-derived the case matrix, authorization, operation accounting,
release identity and ordering, catalog behavior and outcome materializations,
classification compatibility, correctness-only metrics, and projection.

## Adversarial audit

The milestone regression detects 28 adversarial cases, including candidate or
stale proof metadata, wrong values, stale catalogs, family/combination
mismatch, a third axis, active/performance authorization, missing or duplicate
operations and releases, wrong decision/epoch/connection/run, forged release
epoch, contradictory classifications, materialization mismatches, projection
substitution, a performance metric, and stale rollback forcing. Focused
runtime tests separately prove ordinary two-axis configuration and third-axis
joining are denied.

## Validation inventory

The final same-branch validation produced:

| Suite | Valid/warning coverage | Expected-invalid coverage | Result |
| --- | --- | --- | --- |
| foundation | 12 valid fixtures; five canonical documents | 15 fixtures | passed |
| plan compiler and manifest | seven valid plans; five warning plans; 12 warning proofs | 21 plans; six manifest/validation cases | passed |
| runtime evidence | 16 valid fixtures; five warning fixtures | 24 fixtures | passed |
| hardening | nine valid fixtures; six warning fixtures | 20 fixtures; five projection cases | passed |
| evidence-integrity closeout | 15 immutable inputs; nine outcome mappings; 66 classification pairs | ten evidence, eight classification, seven projection cases | passed |
| independent proofs | two candidate bundles; ten operations; five releases | 17 cases | passed |
| send-composition correctness | ten primary documents; one independent review; 11 operations; four releases | 28 adversarial cases | passed |

Both Release builds completed with zero warnings and zero errors. The focused
requirement-home run passed 66 of 66 tests. Direct validation proved the
specification, architecture, work item, and verification documents conform to
the published SpecTrace model; all six requirement allocations and 26 exact
path references resolve. The retained repository-wide core baseline still
fails with 2,961 unrelated existing errors and was not repaired.

## Local commits

The mission branch contains these single-purpose commits after source
`977ea635`:

| Commit | Purpose |
| --- | --- |
| `862bceec` | allocate the correctness milestone |
| `0b6094c1` | derive candidate evidence from production selectors |
| `80113e61` | version regenerated actuation candidates |
| `171b9372` | independently review and promote the exact proofs |
| `122901eb` | retain reviewed actuation evidence inputs |
| `a1dbc5eb` | authorize the exact correctness-only cell |
| `87243f47` | execute the production batch, buffer, owner, and release seams |
| `b1620359` | materialize, project, and independently review the interaction |
| `89dd1913` | preserve retained interaction-plan compatibility |

The terminal documentation/package commit contains this report, final trace
statuses, and the exact validation closeout. Its full identity is recorded
with the archive rather than embedded in its own content.

## Commands

```powershell
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentControl.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentPlanCompiler.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentHardening.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentEvidenceIntegrityCloseout.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeIndependentActuationProof.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeSendCompositionCorrectness.ps1
dotnet build .\src\Incursa.Quic\Incursa.Quic.csproj -c Release --no-restore
dotnet build .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-restore
dotnet test .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~REQ_QUIC_CRT_0219|FullyQualifiedName~REQ_QUIC_CRT_0225"
git diff --check
```

## Boundary and readiness

No BenchmarkDotNet or ProtocolLab campaign ran. No throughput, latency, CPU,
or allocation comparison was collected. No other axis migrated. CI was not
changed, nothing was pushed, and no policy became active.

Measurement-readiness assessment:
`correctness_ready_measurement_still_frozen`.

---
title: "Adaptive Runtime Two-Axis Runtime Evidence Review - 2026-07-25"
---

# Adaptive Runtime Two-Axis Runtime Evidence Review - 2026-07-25

Status: correctness-only runtime/evidence vertical slice complete for
`application_send_batch_formation` and `buffer_copy_coalescing`; measurement
and active behavior remain unauthorized.

Trace: `REQ-QUIC-CRT-0206` through `REQ-QUIC-CRT-0209`,
`ARC-QUIC-CRT-0095`, `WI-QUIC-CRT-0096`, and `VER-QUIC-CRT-0097`.

## Recovery and preservation

The primary worktree remained on `main`, 104 commits ahead of `origin/main`,
with 21 coherent unfinished ACK-profile/Stage 5 files preserved. It was not
reset, cleaned, stashed, rewritten, relabeled, or mixed into this checkpoint.
This checkpoint used the linked worktree
`C:\shared\src\incursa\.worktrees\quic-experiment-runtime-evidence-20260725`,
branch `codex/adaptive-runtime-runtime-evidence-20260725`, from reviewed
compiler commit `aa3b2c7480f1db52e5d7f4df8d1c2f2476a2f73f`.

The foundation validator was clean at recovery: 8 schemas, 5 canonical
documents, 12 valid fixtures, and 15 expected-invalid fixtures. The compiler
validator was also clean: 7 valid, 5 warning, 21 invalid plan fixtures, and 6
invalid validation/manifest link fixtures. No benchmark, campaign, transform,
or other performance process was active.

## Architecture and canonical ownership

The reviewed sequence remains:

`configured_value` -> forced value or shadow recommendation ->
`candidate_value` -> operation eligibility result and reason ->
`applied_value` -> axis mechanism event -> effective behavior ID -> bounded
epoch counts.

`candidate_value` is pre-safety. Plan eligibility remains a static
catalog/plan/family/capability judgment. Operation eligibility is evaluated at
an actual seam opportunity and cannot be replaced by plan eligibility.

| Fact | Canonical owner |
| --- | --- |
| Axis values, boundary, latch, predicates, clamps | axis contract |
| Effective behavior IDs and derivation | effective-behavior catalog |
| Architectural edges | relationship graph |
| Cross-axis legality/capability/equivalence | combination constraints |
| Context, history, metrics, promotion gates | experiment family |
| Requested values and order | source plan |
| Plan classifications and expanded cells | plan-validation result |
| Binary, host, capabilities, executable cells | compiled manifest |
| Actual candidate, eligibility, applied value, mechanism | raw evidence |
| Actual behavior counts and work | materialization |
| Rebuildable joins and analytical classifications | logical projection |

The five reviewed experiment types remain unchanged:

| Type | Validation shape | Current execution posture |
| --- | --- | --- |
| `actuation_validation` | one forced axis; adjacent axes legacy | correctness-only |
| `isolated_counterfactual` | one behavior-distinct varied axis | measurement frozen |
| `interaction_screen` | only approved family axes; constraints applied | capability pending |
| `feedback_loop` | full history/reset/recovery/cooldown/terminal contract | structural only |
| `profile_validation` | transparent per-axis evidence | non-executable first slice |

## Plan/manifest and hashing proof

The source plan remains immutable and pre-build. The dry-run compiled manifest
remains post-validation, post-build, host-bound infrastructure and launches
nothing. The preceding proof retains plan hash
`928762c81b37c3a3a026223c83a5b89e0478c68bb88aa152d82c648f43d461b1`,
validation hash
`45bd451a433fc4f130d96fec6e7ad189de8f4a33311156589e26d547c8729a0c`,
and manifest hash
`6dd5f4741f1ae9e1a4565d4e74f5095f40c093c95e9c1aebc6086d5767aef3e5`.
Those roles remain non-interchangeable.

Runtime-evidence materialization extends the same canonical contract: root
`content_sha256` is excluded, properties and set-like arrays are normalized,
declared order is preserved only where semantic, UTF-8 has no BOM, and SHA-256
is lowercase hexadecimal. Each valid source fixture materializes and projects
twice to byte-identical canonical JSON and identical hashes.

## Batch-formation mechanism report

`QuicApplicationSendBatchOperationEvidence` is a fixed-field record correlated
by epoch, packet-plan decision instance, and operation sequence. The existing
packet-plan sequence truthfully serves both decision and operation identity
because one batch decision owns one plan commit or abandonment; the fields
remain distinct.

The seam records legal/applied write counts and bytes. Derivation is closed:

| Mechanism event | Effective behavior |
| --- | --- |
| legal eligible prefix used | `behavior.application_send_batch_formation.legacy_current.prefix` |
| prefix shortened to one eligible write | `behavior.application_send_batch_formation.single_eligible.prefix` |
| no packet plan | retained inactive/fallback/error classification; no guessed behavior |
| contradictory counts/bytes | explicit unclassifiable evidence; no guessed behavior |

The policy still shortens only. It cannot widen or reorder the legal prefix or
change completion ownership. Congestion, pacing, recovery, flow-control,
packet, queue, lifecycle, cancellation, disposal, terminal, and ownership
guards remain authoritative. Fixed epoch counters retain operation counts and
applied bytes for both materializable behaviors plus inactive, clamped,
unclassifiable, and total legal/applied work.

## Buffer-coalescing mechanism report

`QuicBufferCopyCoalescingOperationEvidence` is emitted only for the actual
combined-send mechanism; broad copy paths are classified
`not_axis_mechanism`. The call site passes the observed owner-rent result rather
than inferring it from the path. Epoch, decision, and operation identity travel
in the fixed lifetime token to the terminal release record, preserving
decision epoch separately from release epoch.

| Mechanism event | Effective behavior |
| --- | --- |
| exact combined prefix retained | `behavior.buffer_copy_coalescing.legacy_current.exact_prefix` |
| lower two-source cap applied | `behavior.buffer_copy_coalescing.memory_conservative.two_source_cap` |
| no owner rented | retained resource-ineligible classification; no guessed behavior |
| broad copy path | rejected as axis behavior |
| contradictory construction | explicit unclassifiable evidence |

The policy remains lower-only and cannot widen or reorder Stage 1 work.
Ownership and terminal release remain authoritative. Fixed epoch counters
retain per-behavior operation counts and applied bytes, inactive/clamped/error
counts, and the existing legal/applied/copy/retention totals.

## Correlation and cross-axis model

The bounded chain is:

`run + binary cohort + connection + epoch + axis + decision instance` ->
operation -> axis-specific mechanism -> optional buffer terminal release ->
effective behavior -> epoch aggregate.

The valid corpus proves both axes distinct, either axis distinct while the
other is structurally inactive, both inactive, and multiple behavior IDs in
one epoch across different operations. It does not assume that
`single_eligible` always deactivates coalescing and does not release generic
interaction execution.

Shadow recommendations are candidate evidence only and do not change the
applied mechanism. Forced candidates remain subject to operation eligibility;
clamped and rejected candidates are retained. A single operation cannot
receive two mutually exclusive behavior IDs.

## Schemas and deterministic materialization

The additive strict schemas are:

- `adaptive-runtime-operation-evidence-v1`;
- `adaptive-runtime-effective-behavior-materialization-v1`; and
- `adaptive-runtime-experiment-evidence-projection-v1`.

The Stage 1 unified raw v1 schema also exposes the new fixed batch behavior
counts. Unknown fields are rejected. Authorization fields are constrained
false.

The materializer resolves the reviewed effective-behavior catalog by document
ID, schema version, document version, and content hash. It derives IDs only
from the two closed axis/mechanism mappings, recomputes operation/work/byte and
fallback/error/inactive/unclassifiable totals, preserves source operation
references, rejects ambiguity, and is idempotent. Throughput, latency, CPU,
allocation totals, and endpoint counters are never derivation inputs.

## Fixture and recomputation proof

The fixture corpus contains:

| Classification | Count |
| --- | ---: |
| valid | 16 |
| warning/retained | 4 |
| expected invalid | 21 |
| expected materializations | 16 |
| expected projections | 16 |

The valid set covers the required distinct, inactive, fallback/clamp,
cross-axis, exact join, multiple-behavior, aggregate, projection, and retained
negative cases. Warning fixtures retain multiple behavior, inactive, fallback,
and verification-only classifications.

The 21 closed invalid results cover missing/duplicate decisions and
operations, wrong axis,
wrong epoch, broad endpoint relabeling, mutually exclusive collisions,
unsupported behavior, stale catalog, aggregate operation/byte mismatch,
missing checksum, invalid result/epoch join, duplicate epoch identity, shadow
actuation, forced eligibility bypass, missing/duplicate release, missing
retention, silent unclassifiable assignment, and unknown fields.

## Logical analytical projection

The projection is a rebuildable JSON view, not a database authority. It
contains plan, validation, manifest, run, host, binary cohort, workload and
requested/effective shapes, connection epochs, per-axis decisions, operations,
behavior aggregates, correctness-only metric observations, checksum inventory,
classifications, and provenance versions.

Uniqueness is enforced for run/connection/epoch, epoch/axis decision, and
epoch/axis/catalog-version/behavior aggregate identities. Operations join
deterministically to decisions and epochs. Buffer operations join to exactly
one terminal release. Invalid, negative, inactive, clamped, fallback,
excluded, and diagnostic classifications remain retained.

## Focused verification

The checkpoint uses only narrow Release builds, focused requirement-home
tests, schema/fixture validation, deterministic fixture materialization, the
foundation/compiler regression validators, direct SpecTrace validation, and
`git diff --check`. No correctness smoke was required because the seam-local
unit and fixture evidence directly exercises actuation and attribution.

Commands and results:

```powershell
dotnet build src/Incursa.Quic/Incursa.Quic.csproj -c Release --no-restore
# 0 warnings, 0 errors

dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-restore -p:BuildProjectReferences=false
# 0 warnings, 0 errors

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-build --no-restore `
  --filter "REQ_QUIC_CRT_0177|REQ_QUIC_CRT_0178|REQ_QUIC_CRT_0179|REQ_QUIC_CRT_0182|REQ_QUIC_CRT_0183|REQ_QUIC_CRT_0190|REQ_QUIC_CRT_0206|REQ_QUIC_CRT_0207|REQ_QUIC_CRT_0208|REQ_QUIC_CRT_0209"
# 166 passed, 0 failed, 0 skipped

pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1
# 3 schemas; 16 valid; 4 warning; 21 invalid; 16 deterministic rebuilds

pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1 -RepositoryRoot .
# 8 schemas; 5 canonical documents; 12 valid; 15 invalid; clean

pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentPlanCompiler.ps1 -RepositoryRoot .
# 7 valid; 5 warning; 21 invalid plans; 6 invalid links; clean
```

`SPEC-QUIC-CRT-EXPERIMENT-CONTROL`, `ARC-QUIC-CRT-0095`,
`WI-QUIC-CRT-0096`, and `VER-QUIC-CRT-0097` each pass direct
`model/model.schema.json` validation. `git diff --check` is clean.

The authoritative commands are recorded in `VER-QUIC-CRT-0097` and
`eng/adaptive-runtime/README.md`. No BenchmarkDotNet, ProtocolLab, performance
campaign, large matrix, dataset transform, normalization, curation, split,
model, CI, or push command is part of this proof.

## Remaining axes, blockers, and Stage 5

Implemented axes outside this slice retain their current mechanism evidence
and still require separately reviewed migration to this generic
operation-correlated materialization contract. `actor_work_quantum` and
`ready_stream_fairness` retain their documented mechanism-boundary blockers.
Stage 5 `congestion_pacing_profile` safety preparation remains separate and
preserved; `ack_behavior_profile`, `crypto_execution_profile`, and
`http3_qpack_profile` remain blocked on their own architecture, safety, force,
and verification contracts.

The next reviewed action should be to review this package and choose one
additional implemented axis for a similarly bounded migration. Do not release
measurement or multi-axis interaction execution as part of that choice.

## Safety result

- Measurement and performance acceptance remain frozen.
- `active_internal` and production policy behavior remain unauthorized.
- Forced modes remain internal correctness infrastructure and bypass no guard.
- No performance campaign, transform, threshold, or model was produced.
- No CI workflow or trigger changed.
- Nothing was pushed.
- Work stops at the two-axis vertical slice.

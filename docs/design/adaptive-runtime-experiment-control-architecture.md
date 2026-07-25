---
title: "Adaptive Runtime Experiment Control Architecture"
---

# Adaptive Runtime Experiment Control Architecture

Status: checkpoint architecture for `REQ-QUIC-CRT-0198` through
`REQ-QUIC-CRT-0201`; measurement remains frozen; `active_internal` and
production authorization remain false

Checkpoint anchor: commit `2c234bc9` records the current implementation
baseline for the adaptive-runtime matrix and the congestion/pacing profile
checkpoint evidence. This document explains how the experiment-control
foundation fits around the already-implemented lower-only seams and the
retained v1 catalog evidence. It does not add a compiler, a runtime path, or
performance-derived behavior.

The requirement home is
[`../../specs/requirements/quic/SPEC-QUIC-CRT-EXPERIMENT-CONTROL.json`](../../specs/requirements/quic/SPEC-QUIC-CRT-EXPERIMENT-CONTROL.json).
The closest supporting architecture and inventory context is in
[`adaptive-runtime-policy-axis-roadmap.md`](adaptive-runtime-policy-axis-roadmap.md),
[`adaptive-runtime-stage1-unified-execution-map.md`](adaptive-runtime-stage1-unified-execution-map.md),
[`adaptive-runtime-policy-observation-schema.md`](adaptive-runtime-policy-observation-schema.md),
[`adaptive-runtime-policy-seam-inventory.md`](adaptive-runtime-policy-seam-inventory.md),
[`../protocol-lab/adaptive-runtime-policy-local-campaign.md`](../protocol-lab/adaptive-runtime-policy-local-campaign.md), and
[`../protocol-lab/adaptive-runtime-policy-dataset-provenance-contract.md`](../protocol-lab/adaptive-runtime-policy-dataset-provenance-contract.md).

## Requirements Satisfied

- `REQ-QUIC-CRT-0198`
- `REQ-QUIC-CRT-0199`
- `REQ-QUIC-CRT-0200`
- `REQ-QUIC-CRT-0201`

## Purpose

This architecture explains how the experiment-control foundation separates
planning, validation, compilation, and runtime evidence for the first
send-composition slice. The plan layer stays portable. The compiled execution
manifest stays host-bound. The runtime evidence stays operation-scoped. The
design reuses the already-implemented send-path seams and preserves the
historical v1 catalog evidence without relabeling it as new planning.

## Scope

In scope for `REQ-QUIC-CRT-0198` through `REQ-QUIC-CRT-0201`:

- planning-time experiment-control facts and their canonical ownership;
- strict v1 schemas for the first slice;
- canonical hashing and deterministic serialization;
- source-plan, validation-result, and compiled-manifest separation;
- the minimal `send_composition` family for the first vertical slice; and
- deterministic fixture validation, including invalid examples.

Out of scope:

- compiler implementation;
- runtime instrumentation changes;
- effective-behavior materialization;
- analytics or offline modeling;
- performance measurement or threshold tuning;
- `active_internal`; and
- production activation.

Frozen state:

- the current one-behavior-distinct-axis runtime capability;
- the retained `schemas/adaptive-runtime-policy-catalog-v1.schema.json`
  evidence;
- the historical producer
  [`eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1`](../../eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1);
- the implemented lower-only seams for `application_send_batch_formation`
  and `buffer_copy_coalescing`; and
- the existing Stage 1 and Stage 2 adaptive-runtime evidence surfaces.

## Design Summary

The source plan declares concrete requested treatment values, their intended
order, experimental factors, context variables, and experiment-family
membership. It does not predict a runtime shadow recommendation, candidate,
operation eligibility result, applied value, or mechanism event.

Validation resolves the plan declarations against the versioned axis,
effective-behavior, relationship, constraint, and family documents. The
validation result owns `plan eligibility`, warnings, errors, equivalence, and
expanded planned cells. It does not decide whether a particular runtime
operation is eligible.

The compiled execution manifest is separate. It carries the committed source
resolution, binary hashes, host fingerprint, resolved capability snapshot,
executable cells, and execution order that only exist after plan validation
and a focused build. Actual operation eligibility, applied values, and
mechanism events remain raw runtime evidence. That split keeps source plans
portable while allowing host-specific execution to be blocked without making
the source plan structurally invalid.

The runtime evidence sequence is fixed:

`configured_value` -> `forced_value` or `shadow_recommendation` ->
`candidate_value` -> `operation_eligibility_result` ->
`operation_eligibility_reason` -> `applied_value` -> `axis mechanism event`
-> deterministic `effective_behavior_id` -> bounded per-epoch counts

One `applied_value` may produce multiple mechanism behaviors, so one epoch may
legitimately contain counts for multiple effective behavior IDs. That fan-out
is derived from axis-specific mechanism events. It does not come from
throughput, latency, CPU, allocation, or another performance measurement, and
no metric may invent a behavior ID.

## Plan And Manifest Split

`REQ-QUIC-CRT-0198` and `REQ-QUIC-CRT-0200` require a strict separation
between planning and compiled execution:

| Layer | Owns | Notes |
| --- | --- | --- |
| Source experiment plan | Concrete requested treatment values, intended ordering, experimental factors, and context variables | Portable pre-build planning input. No binary hash, resolved host capability, or runtime evidence belongs here. |
| Plan validation result | Validation errors and warnings, plan eligibility, expected equivalence, and expanded planned cells | Planning fact only. It can say the plan is structurally valid while its cells remain preparation-only. |
| Compiled execution manifest | Committed source, binary hashes, host fingerprint, resolved capabilities, executable cells, and execution order | Host-bound, post-build control artifact. It does not claim what a runtime operation actually applied. |
| Raw evidence | Actual recommendation, candidate, operation eligibility result and reason, applied value, and mechanism events | Runtime truth. Forced selection never bypasses safety or correctness guards. |
| Effective-behavior materialization | Bounded per-epoch counts derived from mechanism events | Reserved for a later checkpoint; never inferred from performance measurements. |

The current one-behavior-distinct-axis runtime capability makes interaction
plans preparation-valid but compiled execution blocked when the manifest would
require more than one behavior-distinct axis at once. The source plan remains
valid. The compiled manifest is what is blocked.

## Semantic Sequence

`REQ-QUIC-CRT-0198` and `REQ-QUIC-CRT-0200` require the ordered progression
below. The document keeps the sequence visible because the ownership model
depends on it.

1. `configured_value` is authored in the source plan.
2. `forced_value` or `shadow_recommendation` is attached as the counterfactual
   or observe-only overlay.
3. `candidate_value` is the generic pre-safety runtime candidate derived from
   the forced value, shadow recommendation, or configured fallback.
4. `operation_eligibility_result` and `operation_eligibility_reason` are
   emitted at the real operation boundary after all authoritative runtime
   safety and correctness predicates are checked.
5. `applied_value` is the value the runtime actually applies after those
   guards.
6. The axis-specific mechanism event records the mechanism behavior that
   actually ran.
7. `effective_behavior_id` is deterministically derived from the
   axis-specific mechanism event under the versioned effective-behavior
   catalog. Declared context variables and experimental factors may
   disambiguate a catalog rule, but measured outcomes never participate.
8. Bounded per-epoch counts summarize eligible, blocked, applied, and observed
   rows for the epoch.

The sequence is one-way. Later aggregates do not backfill missing operation
evidence, and performance metrics do not participate in the derivation of
`effective_behavior_id`.

## Concept Ownership

`REQ-QUIC-CRT-0198` requires one canonical owner for every experiment-control
fact. The table below keeps that ownership visible.

| Fact | Canonical owner | Why this owner owns it |
| --- | --- | --- |
| Axis identity, authority, values, scope, boundary, latches, predicates, and safety clamps | Axis contract | The seam contract owns its closed domain and lower-only safety boundary. |
| Effective behavior IDs and deterministic derivation | Effective-behavior catalog | Behavior identity is derived from mechanism events, never from measured outcomes. |
| Directed architectural relationships and nominated hyperedges | Relationship graph | Topology has one versioned authority. |
| Cross-axis legality, capability, and equivalence rules | Combination-constraint catalog | Plans and validators reference rules rather than copying them. |
| Workload contexts, metrics, history requirements, and promotion gates | Experiment-family catalog | A family owns its reviewed experimental envelope. |
| Concrete treatment values and intended ordering | Experiment plan | The portable source document states requested treatments before the build. |
| Validation errors, warnings, equivalence, and expanded planned cells | Plan-validation result | These are planning outcomes, not runtime outcomes. |
| Binary, host, capabilities, executable cells, and execution order | Compiled execution manifest | These facts exist only after source resolution, build, hashing, and capability resolution. |
| Actual runtime eligibility and mechanism events | Raw evidence | Runtime guards remain authoritative for each operation. |
| Actual behavior aggregates | Effective-behavior materialization | A later deterministic materializer owns bounded per-epoch counts. |

The generic pre-safety name is `candidate_value`. Existing seam-specific
`selectedValue` fields remain valid historical/runtime compatibility fields:
for those records, `candidate_value = selectedValue` before operation safety
fallback. A validator or adapter must perform that mapping mechanically and
must not reinterpret `selectedValue` as plan eligibility, applied behavior, or
effective behavior.

## Five Experiment Types

`REQ-QUIC-CRT-0198` defines five closed experiment types. These are planning
families, not runtime modes.

| Type | Intended validation semantics |
| --- | --- | --- |
| `actuation_validation` | Exactly one axis may be forced; all other axes remain `legacy_current`. It proves activation wiring, forceability, fallback, safety, telemetry, neutrality, and rollback. Performance conclusions are prohibited. |
| `isolated_counterfactual` | Exactly one behavior-distinct axis varies and every other axis remains fixed. The varied axis must have passed actuation validation. Expected-equivalent cells cannot be represented as distinct performance treatments. |
| `interaction_screen` | Multiple behavior-distinct axes may vary only within an approved experiment family. Axes outside the family remain fixed and every cross-axis constraint must permit the combination. This type does not release the measurement freeze. |
| `feedback_loop` | Multiple explicitly related axes may vary. Warmup, initial state, reset/carryover rules, ordered observations, recovery, cooldown, and terminal handling are mandatory. |
| `profile_validation` | A reviewed transparent profile is the treatment, while per-axis configured, candidate, eligible, applied, and effective-behavior evidence remains mandatory. Opaque profile IDs cannot replace axis evidence. This type is not part of the first implementation vertical slice. |

The key rule is the same across all five types: the source plan may be valid
even when the compiled execution manifest is blocked. That is especially
important for `interaction_screen`, because the current runtime capability
permits only one behavior-distinct axis at execution time.

## Send Composition

`REQ-QUIC-CRT-0200` limits the first vertical slice to the minimal
`send_composition` family needed for planning and validation.

| Member | Role | Relationship |
| --- | --- | --- |
| `application_send_turn_planning` | Behavior-equivalent reference axis | Both configured labels currently map to `legacy_priority_stable_sequence`; comparisons are verification-only until a behavior-distinct planner exists. |
| `application_send_batch_formation` | Directed batch source | Produces the legal prefix that the buffer axis may later consume. |
| `buffer_copy_coalescing` | Directed buffer sink | Applies only after the legal combined-send prefix exists and can lower the contributing source-segment count without widening or reordering work. |

The only directed relationship in the first slice is batch formation to
buffer coalescing. `application_send_turn_planning` remains the
behavior-equivalent reference axis. The old v1 catalog generator remains the
historical compatibility producer; the new suite supersedes its output only
for new experiment-control planning.

### Preserved seam facts

`application_send_batch_formation` has the implemented values
`legacy_current` and `single_eligible`. Its decision occurs after creation of
the legal eligible prefix and before packet-plan commit. Its latch is one
packet plan. Its authority is lower-only: it cannot reorder work or widen the
legal prefix. The values are behavior-distinct only when more than one legal
eligible write exists.

`buffer_copy_coalescing` has the implemented values `legacy_current` and
`memory_conservative`. Its decision occurs after the legal combined-send
prefix exists and before the combined buffer owner is rented and filled. Its
latch is the combined buffer owner's terminal lifetime. Its authority is
lower-only: `memory_conservative` currently caps the operation at two source
segments and cannot widen or reorder work.

`application_send_turn_planning` retains the configured values
`legacy_current` and `conservative`. Both currently map to
`legacy_priority_stable_sequence`, so they are expected-equivalent and cannot
form separate performance treatments.

The `send_composition` family references the exact axis predicates and
correctness/ownership guardrails from the axis and constraint catalogs. Axes
outside the approved family remain fixed. Measurement authorization is false
and promotion policy is deferred. No profile-validation treatment belongs to
this first vertical slice.

## Current Runtime Boundary

The existing runtime already exposes independently forceable lower-only seams
for `application_send_batch_formation` and `buffer_copy_coalescing`. That is
enough to make the first interaction plans structurally valid. It is not yet
enough to compile multi-axis interaction cells that require more than one
behavior-distinct axis at execution time.

This is the reason `REQ-QUIC-CRT-0198` separates source plans from compiled
execution manifests. The source plan can be prepared now. The compiled
manifest can be produced later, once the capability budget is explicitly
expanded.

## Schema Contract

`REQ-QUIC-CRT-0199` requires eight strict self-contained v1 schemas and a
deterministic validator entrypoint. The expected canonical instance paths for
the first slice are shown below.

| Schema | Canonical instance or focused fixture path | Validator path |
| --- | --- | --- |
| `schemas/adaptive-runtime-policy-axis-contract-v1.schema.json` | `eng/adaptive-runtime/experiment-control/adaptive-runtime-policy-axis-contracts-v1.json` | `eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1` |
| `schemas/adaptive-runtime-effective-behavior-catalog-v1.schema.json` | `eng/adaptive-runtime/experiment-control/adaptive-runtime-effective-behavior-catalog-v1.json` | `eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1` |
| `schemas/adaptive-runtime-policy-relationship-graph-v1.schema.json` | `eng/adaptive-runtime/experiment-control/adaptive-runtime-policy-relationship-graph-v1.json` | `eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1` |
| `schemas/adaptive-runtime-combination-constraint-catalog-v1.schema.json` | `eng/adaptive-runtime/experiment-control/adaptive-runtime-combination-constraint-catalog-v1.json` | `eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1` |
| `schemas/adaptive-runtime-experiment-family-catalog-v1.schema.json` | `eng/adaptive-runtime/experiment-control/adaptive-runtime-experiment-family-catalog-v1.json` | `eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1` |
| `schemas/adaptive-runtime-experiment-plan-v1.schema.json` | `tests/fixtures/adaptive-runtime-experiment-control/valid/experiment-plan.*.valid.example.json` | `eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1` |
| `schemas/adaptive-runtime-experiment-plan-validation-v1.schema.json` | `tests/fixtures/adaptive-runtime-experiment-control/valid/experiment-plan-validation.valid.example.json` | `eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1` |
| `schemas/adaptive-runtime-compiled-execution-manifest-v1.schema.json` | `tests/fixtures/adaptive-runtime-experiment-control/valid/compiled-execution-manifest.valid.example.json` | `eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1` |

The validator must reject unknown fields, stale references, unsupported
values, blocked axes, malformed hashes, and fixed/varied overlap. It must
also reproduce lowercase SHA-256 over canonical UTF-8 JSON after excluding the
document's own `content_sha256` field.

Deterministic array handling is strict:

- `treatment_order`, `treatments`, `planned_cells`, `validation_errors`,
  `validation_warnings`, `execution_order`, and `executable_cells` preserve
  their declared order;
- every other array in this suite is set-like and is sorted by the ordinal
  bytes of each item's recursively canonical JSON representation;
- duplicate definitions or edges fail validation.

## Hashing

The canonical hash rule in `REQ-QUIC-CRT-0199` is simple and non-negotiable:
recursively order object properties by ordinal property name, apply the array
ordering rule above, serialize compact canonical UTF-8 JSON without a byte
order mark, exclude only the root document's own `content_sha256` field from
the hash input, compute SHA-256 over those exact bytes, and emit lowercase
hexadecimal. A referenced document's `content_sha256` remains in the input.
The validator must recompute the same digest exactly. The hash is part of the
document contract, not a post-hoc label.

This rule applies to the experiment-control schemas and to the canonical
instances that the validator produces. It does not let a later build step
rewrite the plan or smuggle in performance-derived behavior.

## Legacy Compatibility

`REQ-QUIC-CRT-0200` preserves `schemas/adaptive-runtime-policy-catalog-v1.schema.json`
and `eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1` as a
historical compatibility producer. Their evidence remains preserved. They are
not the new planning authority.

The new experiment-control suite supersedes the old catalog only for new
planning. There is no companion generator/compiler in this checkpoint. The
new suite only explains how the first slice should be planned, validated, and
compiled later.

## Operation Evidence

`REQ-QUIC-CRT-0201` distinguishes operation-scoped evidence from bounded
aggregates.

Operation-scoped evidence includes:

- `operation_eligibility_result`;
- `operation_eligibility_reason`;
- `applied_value`;
- `axis mechanism event`; and
- `effective_behavior_id`.

Bounded aggregates include:

- per-epoch counts of eligible, blocked, and applied rows;
- counts of mechanism events by axis and experiment type;
- counts of effective behaviors by epoch;
- counts of validation failures by stable error code; and
- counts of preparation-only or compiled-blocked cells.

Aggregates summarize operations. They do not create new operation facts.
When the runtime capability blocks an interaction cell, the blocked state
belongs to the manifest and the validator, not to the aggregate.

## Trace Allocation

The checkpoint trace allocation is:

| Home | ID | Role |
| --- | --- | --- |
| Architecture | `ARC-QUIC-CRT-0089` | Canonical architecture home for `REQ-QUIC-CRT-0198` through `REQ-QUIC-CRT-0201` |
| Work item | `WI-QUIC-CRT-0090` | Canonical implementation work-item home for the first experiment-control slice |
| Verification | `VER-QUIC-CRT-0091` | Canonical deterministic validation home for the schema and fixture set |
| Architecture | `ARC-QUIC-CRT-0092` | Deterministic validator, compiler, equivalence, hashing, and dry-run manifest architecture |
| Work item | `WI-QUIC-CRT-0093` | Compiler and dry-run manifest implementation |
| Verification | `VER-QUIC-CRT-0094` | Compiler fixtures, hash proofs, focused build, and dry-run manifest proof |

These homes are paired with the requirement set in
`SPEC-QUIC-CRT-EXPERIMENT-CONTROL`. The foundation requirements remain
`REQ-QUIC-CRT-0198` through `REQ-QUIC-CRT-0201`; the compiler checkpoint uses
`REQ-QUIC-CRT-0202` through `REQ-QUIC-CRT-0205`. The focused compiler design is
recorded in
[`adaptive-runtime-experiment-plan-compiler.md`](adaptive-runtime-experiment-plan-compiler.md).

## Risks

- A source plan can be structurally valid while its compiled execution is
  blocked by capability. That is intended, but it can be misread as a failed
  plan if the split is not kept visible.
- A single `applied_value` can map to multiple bounded effective behaviors in
  one epoch. If the catalog does not declare that fan-out explicitly, a later
  compiler could appear nondeterministic.
- Performance metrics can correlate with behavior, but they are not allowed
  to define `effective_behavior_id`. If that boundary is blurred, the
  experiment-control foundation collapses into analytics.
- The old v1 catalog remains preserved evidence. If a future slice rewrites it
  instead of superseding it, the compatibility story becomes dishonest.

## Open Questions

The compiler checkpoint resolves the prior planning questions as follows:

- interaction cells remain plan-valid and `capability_pending`;
- expected behaviors are a bounded class list, while actual fan-out remains
  raw evidence and later materialization;
- plan, validation, and manifest documents retain the reviewed canonical JSON
  hashing rule and reject cross-role hash substitution by exact references;
  and
- preparation-only axes are structurally representable but compile as
  `invalid`, while first-slice deferred feedback/profile cells remain
  structurally inactive.

The first runtime/evidence vertical slice now closes those questions for
`application_send_batch_formation` and `buffer_copy_coalescing` only:

- fixed-field seam evidence preserves pre-safety candidate, independent
  operation eligibility, applied value, axis-specific mechanism event, legal
  and applied work, and bounded decision/operation/epoch correlation;
- buffer construction identity is carried to exactly-once terminal release;
- the deterministic materializer resolves the catalog by identity, version,
  and hash and rejects broad endpoint, wrong-axis, ambiguous, stale, or
  unclassifiable attribution;
- fixed epoch aggregates permit several behavior IDs across different
  operations and retain per-behavior counts and work bytes; and
- the logical projection rebuilds from immutable checksummed fixtures.

This closure is trace-owned by `REQ-QUIC-CRT-0206` through
`REQ-QUIC-CRT-0209` and reviewed in
`docs/testing/adaptive-runtime-experiment-runtime-evidence-2026-07-25.md`.
Other axes, live campaign retention, interaction execution, measurement, and
activation remain outside this checkpoint.

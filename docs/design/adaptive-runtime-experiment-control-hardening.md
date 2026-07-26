# Adaptive-runtime experiment-control hardening

Status: reviewed correctness-only architecture decision  
Source checkpoint: `c7076b191f6f0b3f3d3ee94b477746fc286f4144`  
Scope: `application_send_batch_formation` and `buffer_copy_coalescing`

This decision corrects the experiment-control ownership and evidence boundaries
found by the same-commit consolidation audit. It does not migrate an axis,
release interaction execution, authorize measurement, activate
`active_internal`, or authorize production behavior.

## Compatibility boundary

All v1 schemas, canonical documents, fixtures, expected outputs, and retained
evidence remain valid under their original versions. Incompatible semantics
are additive:

| Concern | Retained contract | Hardened contract |
| --- | --- | --- |
| Behavior derivation and expected behavior sets | effective-behavior catalog v1 | effective-behavior catalog v2 |
| Axis relationships | relationship graph v1 | relationship graph v2 |
| Experiment family | family catalog v1 | family catalog v2 |
| Operation correlation | operation evidence v1 | operation evidence v2 |
| Behavior aggregate | materialization v1 | materialization v2 |
| Non-behavior accounting | none | operation-outcome materialization v1 |
| Expanded plan cells | validation v1 | validation v2 |
| Analytical projection | projection v1 | projection v2 |

Readers and validators select a contract explicitly by `schema_version`.
Unknown versions fail closed. No v2 interpretation is retroactively applied to
a v1 artifact.

## Canonical ownership

| Fact | Canonical owner |
| --- | --- |
| Legal axis values, scope, latches, safety, activation, and readiness | Axis contract |
| Exact mechanism-event-to-behavior derivation, behavior composition, primary/possible behavior sets, and outcome vocabulary | Effective-behavior catalog |
| Axis-level architectural relationships | Relationship graph |
| Cross-axis legality and capability | Combination-constraint catalog |
| Included/fixed axes, contexts, workloads, metrics, history, and promotion | Experiment-family catalog |
| Requested treatments and order | Immutable experiment plan |
| Expanded signatures, equivalence, warnings, and plan eligibility | Plan validation |
| Runtime decision, operation, release, and mechanism facts | Raw operation evidence |
| Derived behavior aggregates | Effective-behavior materialization |
| Non-behavior outcome aggregates | Operation-outcome materialization |
| Rebuildable analytical joins and append-only classifications | Analytical projection |

Downstream artifacts reference the canonical owner by document identity,
version, and content hash. They do not copy a second executable rule.

## Decision 1 — behavior and outcome aggregates are separate

An effective-behavior aggregate represents only operations for which the
versioned catalog produces exactly one permitted behavior result (or an
explicitly permitted composed result). It is keyed by run, connection, epoch,
axis, catalog version, and behavior ID.

An operation-outcome aggregate represents bounded non-behavior outcomes:
`inactive`, `fallback`, `clamped`, `invalid`, `negative`, `error`,
`unclassifiable`, `diagnostic`, and `terminal_release_failure`. It is keyed by
run, connection, epoch, axis, outcome-contract version, and outcome ID.

An operation may contribute to one behavior aggregate and one truthful outcome
aggregate when, for example, a fallback still executes a catalogued safe
mechanism. An operation with no materialized behavior contributes only to its
outcome aggregate. Accounting records the source operation IDs, and a
reconciliation result proves that every source operation appears in the
appropriate aggregate without duplicate contribution to the same aggregate
kind. Fake behavior IDs are prohibited.

## Decision 2 — expected behavior is set-based

For each axis value the catalog owns three sorted sets:

- `primary_expected_behavior_ids`: behavior-distinct mechanisms directly
  represented by the value when its activation contract is satisfied;
- `possible_effective_behavior_ids`: all catalogued mechanisms that may occur
  for the candidate because of operation shape, inactivity, fallback, or
  clamping;
- `non_behavior_outcome_ids`: possible non-behavior outcomes.

Expected-cell equivalence compares the primary behavior signature together with
the reviewed activation/distinctness signature. Overlap in possible behavior
or fallback sets does not make treatments equivalent. Multiple primary
behaviors are legal only when the catalog entry explicitly declares the set and
composition/alternative semantics.

The known send-turn labels remain a true equivalence: `legacy_current` and
`conservative` share the same primary behavior
`behavior.application_send_turn_planning.legacy_priority_stable_sequence` and
collapse to verification-only. Batch and buffer values may share a safe
fallback mechanism without collapsing their distinct primary signatures.

## Decision 3 — relationship graph v2 is axis-oriented

The v2 primary graph uses axis IDs for edge endpoints and closes relationship
type to:

- `authority_overlap`
- `structural_constraint`
- `supplies_work`
- `changes_observed_state`
- `feedback_loop`
- `shared_outcome_only`
- `context_effect`

Every edge records an edge ID, source and target axis IDs, mechanism,
confidence, evidence level, evidence references, experiment requirement, and
reviewed version. Nominated hyperedges also use axis IDs. Optional conditions
may reference behavior IDs, but behavior-level conditions do not replace the
axis-level relationship.

The current batch-to-buffer relationship migrates as `supplies_work`: batch
formation supplies the already legal combined-send prefix considered by buffer
coalescing. The v1 behavior-oriented edge remains retained evidence.

## Decision 4 — experiment-family catalog v2 separates factors and context

The v2 family contract has distinct fields for:

- `included_axis_ids`;
- `fixed_axis_requirements`;
- `outer_context_ids`;
- `workload_archetype_ids`;
- `primary_metric_ids`;
- `guardrail_metric_ids`;
- predicate, relationship, and constraint references;
- `history_reset_requirements`;
- supported and blocked experiment types;
- measurement authorization and promotion status.

Compiler family membership uses `included_axis_ids` and
`fixed_axis_requirements`. Outer context and workload archetypes are offline
experiment inputs and are prohibited as runtime controller inputs. The v1
property `contexts` remains a compatibility field and is not the v2
axis-membership authority.

## Decision 5 — future interaction screens require independent actuation proof

Before a measurement-capable interaction screen can become execution-eligible,
every behavior-distinct varied axis/value must have reviewed independent proof
for actuation, safety, fallback, and rollback. Proof is not inferred from an
interaction fixture.

While measurement remains frozen, a structurally valid interaction plan may be
compiled for correctness verification. Missing proof produces
`interaction_actuation_proof_missing` and the plan is `verification_only` or
`blocked_for_measurement`; it is never silently made performance-executable.
This decision does not release the existing send-composition capability block.

## Decision 6 — projection building accepts immutable inputs

The general v2 projection builder accepts explicit paths or document references
for the plan, plan validation, compiled manifest, run, host, binary cohort,
requested and effective workload, operation evidence, behavior materialization,
outcome materialization, artifact/checksum inventory, and classifications or
exclusions.

Every input is schema-validated where a schema is available, content-hashed,
and cross-checked against its references. No general builder path contains a
fixture directory, placeholder hash, implicit host identity, or mutable
database dependency. A thin fixture harness may call the general builder.
Repeated builds over the same immutable inputs are byte-identical and
hash-identical. Missing, stale, or mismatched inputs fail closed.

The projection is rebuildable analytical state. The authority chain remains:

```text
immutable plan
  -> immutable validation and compiled manifest
  -> checksummed raw evidence
  -> behavior and outcome materializations
  -> rebuildable projection
```

## Correlation and derivation contract

For v2 evidence, each operation repeats the immutable correlation and decision
facts necessary for exact reconciliation: run ID, connection key, epoch,
axis ID, decision instance ID, configured value, forced value, shadow
recommendation, pre-safety candidate, eligibility result and reason, applied
value, exact canonical `mechanism_event_id`, fallback/safety reason, work, and
terminal outcome.

The materializer resolves:

```text
axis_id
  + mechanism_event_id
  + operation scope/version
  -> exact catalog match
  -> effective_behavior_id
```

Zero matches produce `behavior_derivation_no_match` and an explicit
unclassifiable outcome. Multiple mutually exclusive matches produce
`behavior_derivation_ambiguous`. Composition is permitted only when the catalog
declares it. Throughput, latency, CPU, allocations, and other performance
measurements are never inputs.

Every decision, operation, result, release, and classification resolves to a
real run/connection/epoch identity. Release order is monotonic relative to
decision/owner creation, terminal release is exactly once, classifications
have unique IDs and exact target identity, and retained classifications cannot
be borrowed from another operation.

## Closed safety posture

All new documents require:

```text
active_behavior_authorization = false
performance_acceptance_authorization = false
```

Forced values never bypass operation eligibility or transport safety. No
runtime dictionary, boxing, unbounded retention, service location, model
loading, online learning, controller identity input, performance campaign, CI
change, axis migration, or production activation is authorized by this
decision.

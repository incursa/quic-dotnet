---
title: "Independent Adaptive-Runtime Actuation-Proof Candidates"
---

# Independent Adaptive-Runtime Actuation-Proof Candidates

Status: accepted architecture for a correctness-only candidate-proof
checkpoint; external review, measurement, and active behavior remain
unauthorized.

## Scope

This checkpoint corrects complete release operation resolution and produces
independent candidate proofs for:

- `application_send_batch_formation = single_eligible`;
- `buffer_copy_coalescing = memory_conservative`.

Each proof uses its own `actuation_validation` plan. The other migrated axis
and every adjacent axis remain `legacy_current`. No interaction cell is
executed and the runtime's one-behavior-distinct-axis limit is unchanged.

## Release Resolution

The release resolver matches one operation using the full
`operation_identity_v1` component set:

```text
run_id
+ connection_key
+ operation_epoch_sequence
+ axis_id
+ decision_instance_id
+ operation_id
```

It does not locate an operation by a smaller tuple and compare the decision
later. The resolved operation then locates exactly one decision. The copied
decision epoch remains an assertion, never an authority. Release epoch
existence, ordering, and exactly-once terminal release remain mandatory.

## Evidence Bridge

The bridge is offline tooling. A focused mechanism harness captures the
existing bounded policy evidence structs and release observations. It does
not infer facts from expected fixture values or from performance results.

The bridge requires one axis per capture and assembles:

```text
plan
-> plan validation
-> compiled execution manifest
-> experiment run
-> host fingerprint
-> binary cohort
-> workload instance
-> requested workload shape
-> effective workload shape
-> operation evidence v3
-> behavior materialization v3
-> outcome materialization v2
-> correctness-only metric observations
-> artifact inventory
-> classifications
-> analytical projection v3
-> candidate proof evidence v1
```

The materializers continue to resolve the exact v2 effective-behavior catalog
offline. Projection construction independently recomputes both
materializations before accepting them. No runtime catalog lookup, generic
hot-path profile, dictionary, boxing, global lock, or unbounded retention is
introduced.

## Candidate Proof Contract

`adaptive-runtime-actuation-proof-evidence-v1` is an external-review handoff.
It references the complete immutable chain and identifies the positive,
fallback, shadow, rollback, inactive, and terminal-release evidence by exact
composite identity.

The document requires:

- `review_status = candidate`;
- `review_outcome = null`;
- `active_behavior_authorization = false`;
- `performance_acceptance_authorization = false`;
- no performance metric as a correctness assertion or proof input.

The canonical family catalog remains unchanged. A separate unapplied patch
shows the metadata that an external reviewer could promote later. Applying
that patch is outside this checkpoint.

## Batch Proof

The positive batch operation requires more than one legal eligible write,
candidate and applied value `single_eligible`, eligible operation state, and
the emitted `mechanism_event.batch_single_eligible`. The selected prefix is
exactly one write, never wider than the legal prefix, and retains the first
legal write so priority and same-stream ordering remain authoritative.

Separate operations retain:

- one-write structural inactivity;
- forced candidate safely clamped or replaced by a guard;
- shadow recommendation with legacy applied mechanism;
- rollback to `legacy_current` and the exact legal eligible prefix.

## Buffer Proof

The positive buffer operation requires more than two legal source segments,
candidate and applied value `memory_conservative`, eligible operation state,
and `mechanism_event.buffer_two_source_cap`. Exactly two source segments are
applied. The owner is rented after the decision and carries the decision and
operation identity through terminal release.

Separate operations retain:

- no-owner or structurally inactive behavior;
- forced candidate safely clamped or replaced;
- shadow recommendation with the exact legacy prefix applied;
- cancellation or disposal ownership safety;
- rollback to `legacy_current` and the exact legal prefix;
- exactly one terminal release for every materialized combined owner.

## Determinism And Negative Cases

Repeated bridge execution over the same capture, binary, host, plan, and
catalog must produce identical canonical bytes and hashes. Meaningful changes
must alter the affected hash.

Closed negative cases cover unreached activation, ineligible positive claim,
safe replacement, shadow actuation, wrong mechanism event, missing decision
or operation, missing or duplicate buffer release, stale catalog, manifest,
source, or binary, wrong run or connection, inactive positive claim,
performance proof input, self-issued reviewed or passed status, and two
behavior-distinct forced axes.

## Frozen Boundary

These proofs establish correctness and attribution only. They do not authorize
measurement, performance comparison, interaction execution, another axis,
multi-axis runtime capability, `active_internal`, or production behavior.

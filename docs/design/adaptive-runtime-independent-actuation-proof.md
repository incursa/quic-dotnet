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

## Completed Candidate Evidence

The batch candidate contains five runtime-derived operations and no releases.
Its immutable chain materializes five behavior aggregates, two outcome
aggregates, and a 15-input analytical projection. The final hashes are:

- operation evidence:
  `76f42043918cf99d41dfa97d50083b028c27dc460e0494979281116bfc50f3c7`;
- behavior materialization:
  `6a2cbafc27ee98e833c3c73b5d308da2e17dcf39d3a317a132e48841df52052a`;
- outcome materialization:
  `b55c03a4e82717868dcae6227db06127c0e5dabff9c052d43990e9d042dd9c3e`;
- projection:
  `e1c2e7144a2e1f55e65c294268967ede7e111469345f68be3be2e435aed25712`;
- proof candidate:
  `9b8930dfe177f028bae00ea61e1f23389f77a2f4cce5c624d5838c7318a1b5e1`.

The buffer candidate contains five runtime-derived operations and five exact
terminal releases. Its immutable chain materializes five behavior aggregates,
two outcome aggregates, and a 15-input analytical projection. The final hashes
are:

- operation evidence:
  `fe5626f5bcb543eae612289ddaee171a9e3d9f8116e1278344bb0629b24cb2b9`;
- behavior materialization:
  `bd6b17696d4c1e4efb3eb768ea076b210159fca9703aa3a7c4bf4a0ed7688ed7`;
- outcome materialization:
  `55bff657b1b8f3590c4ad4dd362f03d7fab9f6bf9cef105139b1f45449a5fa26`;
- projection:
  `7e925302bf5ad341359abaab1ed994f0563c5cbc273c1caa53a18a6b01982ea5`;
- proof candidate:
  `8830a37735e7cb8cd361dacfc69da9824dfe6916e29686192a46ea144d4d1760`.

Both candidates retain `review_status = candidate`,
`review_outcome = null`, performance authorization false, and active behavior
authorization false. The canonical family catalog is unchanged.

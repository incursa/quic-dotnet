---
title: "Adaptive Runtime Deterministic Experiment-Plan Compiler"
---

# Adaptive Runtime Deterministic Experiment-Plan Compiler

Hardening addendum: `-CatalogContractVersion v2` preserves all primary and
possible behaviors, non-behavior outcomes, and activation signatures rather
than selecting the first match. Each forced varied interaction axis/value must
resolve to one reviewed passed v1 actuation proof. The canonical readiness
catalog contains none, so interaction correctness compilation remains
inspectable but is `blocked_for_measurement`.

Status: compiler and dry-run manifest checkpoint; measurement and active
behavior remain unauthorized

Trace: `REQ-QUIC-CRT-0202` through `REQ-QUIC-CRT-0205`,
`ARC-QUIC-CRT-0092`, `WI-QUIC-CRT-0093`, and `VER-QUIC-CRT-0094`

This document extends, and does not replace,
[`adaptive-runtime-experiment-control-architecture.md`](adaptive-runtime-experiment-control-architecture.md).
The reviewed architecture remains authoritative for concept ownership,
effective-behavior semantics, hashing, source-plan immutability, and the
separation between planning and runtime evidence.

## Pipeline

The compiler performs these layers in order:

1. load the source plan and the five canonical authority documents;
2. validate JSON Schema, root hashes, versions, and content-hash references;
3. validate authorization, axis readiness, and prohibited controller inputs;
4. validate experiment-type axis counts and feedback/profile contracts;
5. validate family membership, fixed-axis values, and cross-axis constraints;
6. validate capability expectations and canonical predicate references;
7. resolve treatments to axis values and expected effective behaviors;
8. classify configured cells;
9. reduce expected-behavior equivalence groups and deterministic counts; and
10. hash the canonical validation result.

An invalid plan remains invalid. A structurally valid plan may instead be
`capability_pending`, `verification_only`, or a valid first-slice
classification without becoming runtime-operation eligible.

## Classification precedence

Authorization, schema, hash, version, reference, readiness, and legality
errors produce `invalid`. With no errors:

- feedback-loop and transparent-profile documents retain their structural
  valid classifications while their first-slice cells remain inactive;
- cells blocked only on host or current multi-axis capability produce
  `capability_pending`;
- a plan whose configured alternatives all resolve to one expected behavior
  produces `verification_only`; and
- remaining plans use the experiment-type-specific valid classification.

Warnings never authorize measurement or active behavior.
`measurement_freeze_active` is emitted for every validation result.

## Cell expansion

The source plan owns ordered configured cells. The compiler does not invent a
runtime operation or infer an effective behavior from throughput, latency,
CPU, allocation, or other measurements.

Each configured cell receives:

- its stable source `cell_id` and `cell_order`;
- resolved treatment and axis identities;
- expected effective-behavior class IDs;
- a deterministic equivalence-group ID;
- an execution-planning state; and
- closed reason codes.

Planning states are `executable`, `structurally_inactive`,
`capability_pending`, `rejected`, `deduplicated`,
`retained_for_verification`, `behavior_distinctness_unknown`, and `blocked`.
These remain plan classifications rather than runtime operation eligibility.

## Expected equivalence

Equivalence derives from the effective-behavior catalog. Configured labels are
not behavior identities.

`application_send_turn_planning=legacy_current` and
`application_send_turn_planning=conservative` both resolve to
`behavior.application_send_turn_planning.legacy_priority_stable_sequence`.
The actuation fixture therefore has two configured cells and one expected
effective cell, emits
`all_configured_values_collapse_to_one_expected_behavior`, preserves both rows
for verification, and prohibits performance comparison. The isolated fixture
deduplicates the second expected-equivalent row.

## Canonical hashing

The common module extends the reviewed v1 convention:

- canonical UTF-8 JSON without a byte-order mark;
- exclusion of only the root `content_sha256`;
- ordinal property ordering;
- canonical sorting for set-like arrays;
- preservation of treatment, planned-cell, validation-finding, observation,
  and execution order where declared meaningful; and
- lowercase SHA-256.

Repeated validation output is byte-identical. Changing only the self-hash or
the order of a set-like axis array does not alter the hash. Changing treatment
order or candidate content does. Plan, validation, and manifest hashes occupy
different reference slots and are checked against their referenced document;
one cannot substitute for another.

## Dry-run compiled manifest

`New-AdaptiveRuntimeCompiledExecutionManifest.ps1` runs only after a successful
validation, exact committed-source resolution, a clean worktree check, a
focused build, binary and runner hashing, host fingerprinting, and explicit
capability resolution.

The manifest records executable, capability-ineligible, and excluded cells;
deterministic or seeded-random execution order; output roots; retention rules;
and expected result schemas. It does not mutate the source plan and contains
no launch path.

The committed dry-run proof under
`eng/adaptive-runtime/experiment-control/proofs/` identifies a Release test
binary only. It is provenance proof, not benchmark or campaign evidence.

## Current capability boundary

The `send_composition` interaction plan is structurally legal and expands to
four expected-distinct configured cells. The reviewed constraint catalog still
marks current multi-axis capability blocked, so all four cells are
`capability_pending` and none are executable. This compiler does not modify
the runtime one-behavior-distinct-axis guard.

## Remaining boundary

The next checkpoint must define operation-correlation identifiers and raw
mechanism evidence before a compiled cell can be reconciled with actual
operation eligibility, applied values, mechanism events, or effective-behavior
materialization. This checkpoint does not begin that work.

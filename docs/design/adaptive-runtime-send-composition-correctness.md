---
title: "Adaptive-runtime send-composition correctness execution"
---

# Adaptive-runtime send-composition correctness execution

Status: proposed correctness-only implementation decision.

This decision extends the accepted experiment-control chain only far enough to
review the two existing actuation candidates and execute one approved,
manifest-bound `send_composition` interaction. Performance measurement,
`active_internal`, production selection, another axis, and general multi-axis
configuration remain unauthorized.

## Candidate review and promotion

The candidate documents remain immutable review inputs. A passed proof is
represented by a separate `adaptive-runtime-actuation-proof-review-v1`
document that identifies the exact candidate, independently recomputed
authority-chain hashes, source commit, binary identity, catalog versions,
positive operation, fallback, shadow, rollback, and terminal release.

The reviewer derives its result from document content and recomputation. It
does not use filenames, candidate assertions, prior summaries, or the
unapplied promotion patch as authority. A stale or unavailable recorded binary
requires a new candidate execution against a newly committed source and exact
focused-build identity; it is not waived.

Only these pairs may be promoted:

| Axis | Value |
| --- | --- |
| `application_send_batch_formation` | `single_eligible` |
| `buffer_copy_coalescing` | `memory_conservative` |

The v2 family catalog references passed review records. Original candidates
remain retained.

## Correctness-only authorization

Multi-axis forcing remains denied by default. A new versioned authorization
document is the offline owner of permission for one exact cell. It binds:

* `interaction_screen`;
* the `send_composition` family;
* `execution_purpose = correctness_only`;
* the exact plan, validation, compiled manifest, cell, and source commit;
* both exact passed review records;
* current axis, behavior, relationship, family, and combination-constraint
  documents;
* `single_eligible` and `memory_conservative`;
* all outside axes at `legacy_current`;
* active and performance authorization false.

The compiler and manifest carry this identity. The runtime receives a compact,
immutable, fixed-field snapshot only. The snapshot is internal, cannot be
supplied through ordinary public connection configuration, contains no
dictionary or service locator, and is accepted only when the exact two enum
values and exact manifest cell identity match. It is not a general controller,
does not load catalogs, and cannot authorize production or performance use.

## Mechanism execution

The correctness harness invokes the production selectors and evidence seams:

1. batch legal-prefix construction and
   `QuicApplicationSendBatchPolicy.SelectWriteCount`;
2. batch decision and operation-evidence creation;
3. `QuicBufferCopyPolicy.Evaluate` and its applied segment count;
4. `QuicConnectionRuntime.TryPublishBufferCopyObservation`;
5. the owner lifetime token; and
6. `IQuicBufferCopyOperationObserver.ObserveBufferRelease`.

Expected selected or applied counts are never passed as evidence truth when a
production selector owns them.

The established `supplies_work` relationship matters: when
`single_eligible` actuates, it supplies one selected write, so a buffer
two-source cap cannot also actuate on that same operation. The interaction
cell therefore proves both values across separate, exactly attributable
opportunities in the same authorized cell. It also proves each mixed
distinct/inactive case, both inactive, fallback, shadow neutrality, rollback,
and exactly-once owner release. This is a truthful cell-level interaction,
not a claim of impossible same-operation dual actuation.

## Evidence and review

The interaction bridge produces the existing fifteen immutable projection
inputs, plus the authorization, interaction proof, and independent review
result. Behavior and outcome materializations are catalog-derived and
recomputed before projection. Composite operation identity remains:

```text
run_id + connection_key + epoch_sequence + axis_id
       + decision_instance_id + operation_id
```

Every owner release resolves the complete operation and decision identity.
Every operation is accounted for independently in behavior and outcome
aggregate kinds. Correctness metric observations may count operations,
segments, bytes, releases, and assertions; performance metric IDs or
comparative conclusions invalidate the proof.

The independent interaction reviewer does not trust the proof's claimed
result. It recomputes authorization, mechanism derivation, materializations,
classifications, releases, projection, rollback, and hashes. The review may
issue `passed`, `failed`, or `inconclusive`.

## Frozen boundary

This decision does not authorize:

* performance measurement or measurement release;
* throughput, latency, CPU, allocation, or scaling comparison;
* another axis or family;
* general production multi-axis forcing;
* runtime catalog lookup, model loading, or online selection;
* `active_internal` or production activation;
* CI changes or push.

The strongest permitted readiness result is
`correctness_ready_measurement_still_frozen`.

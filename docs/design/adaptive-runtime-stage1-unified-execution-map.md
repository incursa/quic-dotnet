---
title: "Adaptive Runtime Stage 1 Unified Execution Map"
---

# Adaptive Runtime Stage 1 Unified Execution Map

Status: approved implementation map; active behavior unauthorized

This map applies the policy-axis roadmap's one-axis-at-a-time rule at the
counterfactual-treatment boundary. All implemented Stage 1 axes are observed
in every relevant connection epoch. A campaign may force or vary exactly one
axis while every adjacent axis applies `legacy_current`.

## Recovery Checkpoint

The single-axis dataset transform
`application-send-turn-neutrality-download-20260724-r002` was stopped on
2026-07-24 at the user's direction. The five local results and 55,658 raw
application-send-turn epochs remain append-only. The only completed transform
layer is the policy catalog. The unfinished normalized dataset is
`diagnostic_incomplete`; it must not be restarted, promoted, or used for rule
derivation.

The repository worktree was clean at the stop boundary. Local commit
`aeb6ca32` is the evidence checkpoint at which the campaign binaries and
transform were built. Nothing was pushed.

## Implemented Starting Point

`application_send_turn_planning` currently provides:

- closed `legacy_current` and `conservative` campaign identities;
- connection-construction forcing that bypasses selection but not scheduler
  validation or transport guards;
- disabled, observe-only, and shadow modes;
- a bounded planning snapshot of at most 64 writes and 12 stream identities;
- one-actor-turn observation and snapshot lifetimes;
- deterministic missing, stale, saturated, contradictory, resource, recovery,
  terminal, and out-of-domain fallback reasons;
- separate versioned raw observation and construction-provenance streams;
- raw-to-epoch conversion, checksums, replay, local campaign control, and
  force-legacy rollback; and
- no behavior-distinct active selector. `legacy_current` remains applied.

Its missing Stage 1 work is to publish through a common four-axis epoch
envelope, report adjacent-axis state in every epoch, expose a deterministic
join key for separate construction records, and make bounded evidence-publisher
loss visible. The existing single-axis v1 artifacts remain valid historical
evidence and are not rewritten into v2.

## Remaining Axis Inventory

| Axis | Legacy implementation | Initial closed values | Boundary and latch | Missing minimum seam |
| --- | --- | --- | --- | --- |
| `application_send_batch_formation` | `QuicApplicationSendScheduler` calls `QuicApplicationSendQueue.SelectQueuedApplicationSendBatchCount` to fill the already-computed payload budget; raw stream data stays single. | `legacy_current`, `single_eligible` | One packet plan; latched until that plan commits or aborts. | Implemented: connection-local forcing, lower-only selection, observe/shadow decision, bounded validity and safety reasons, plan outcome, listener copy, replay, guarded sink, and force-legacy rollback. Still open: unified raw export, permanent campaign control, BenchmarkDotNet cost evidence, full Release, and multi-host verification. |
| `queued_send_burst_budget` | `QuicSendPolicy` caps queued work at 4 datagrams before handshake confirmation and 12 after, then congestion and anti-amplification reduce the legal budget. | `legacy_current`, `single_datagram` | One actor turn; an in-progress packet plan remains latched. | Connection-local lower-only cap, observe/shadow snapshot, requested/legal/applied cap outcome, burst-hit/follow-on counters, force-legacy rollback. |
| `oversized_write_admission_quantum` | At logical-write admission, the retained selector chooses two 32 KiB chunks per actor turn only with a dispatcher and 16-24 distinct observed streams; otherwise one chunk. | `legacy_current`, `single_fragment`, `bounded_multi_fragment` | Logical-write admission; immutable through fragmentation, continuation, cancellation, disposal, and completion. | Explicit mode stored with the completion, observe/shadow admission snapshot, quantum/continuation outcome, internal force seam, exact rollback. |

`receive_credit_publication` remains preserved and applies
`legacy_current` throughout Stage 1 send-path campaigns.

## Unified Epoch Contract

The new schema home is
`schemas/adaptive-runtime-stage1-unified-epoch-v1.schema.json`. One document is
one bounded connection epoch and contains exactly one record for each of:

1. `application_send_turn_planning`;
2. `application_send_batch_formation`;
3. `queued_send_burst_budget`; and
4. `oversized_write_admission_quantum`.

The envelope retains:

- `schemaVersion`, `rowId`, campaign/run/cell/sample identity, connection key,
  epoch index, start, and duration;
- exact repository, binary, host, workload, source-artifact, and
  transformation provenance;
- correctness and fairness flags;
- epoch-attributable outcomes; and
- analysis-only workload identity explicitly excluded from production
  features.

Every axis record contains:

- stable `axisId`;
- observation, rule, snapshot, reason, and provenance versions;
- an axis-specific bounded observation object;
- common missing, stale, saturated, contradictory, and out-of-domain flags;
- nullable forced value and shadow recommendation;
- selected and applied values;
- selection source and bounded reason code;
- safety-override state and reason;
- decision boundary;
- latch lifetime and current latch state;
- fallback state; and
- axis-attributable outcomes with an explicit `epoch`, `operation`, `plan`,
  `actor_turn`, or `sample_descriptive_only` scope.

The array is fixed at four records. The validator, not JSON Schema alone,
enforces exactly-once axis IDs, the required Stage 1 order, closed policy
values, and the campaign invariant that at most one record has a non-null
forced value or behavior-distinct treatment.

Scenario name, payload constants, requested concurrency, peer identity, URLs,
and application identity remain analysis-only provenance and are prohibited
from every axis observation and production feature object.

## Separate Construction And Operation Records

Policy-specific construction, packet-plan, actor-turn, and logical-write
records remain separate from the unified epoch. They are never silently
combined with observation rows.

The deterministic join key is:

```text
campaignId | runId | cellId | sampleId | connectionKey |
epochIndex | axisId | decisionSequence
```

Operation-latched records additionally carry a stable `operationKey`;
packet-plan records carry a stable `planKey`. The validator requires every
record to join one unified epoch and one axis record, rejects duplicate keys,
and verifies forced, selected, and applied identities. Sample-scoped outcomes
remain labeled `sample_descriptive_only` and are not treated as independent
epoch labels.

## Correctness Guards And Trace Homes

The following IDs were checked as unused before reservation:

| Scope | Requirement home | Guard summary |
| --- | --- | --- |
| Unified four-axis envelope and joins | `REQ-QUIC-CRT-0177` | Exactly four axis records; one varied axis; adjacent `legacy_current`; closed versions and values; deterministic join; forbidden production inputs absent. |
| Batch formation | `REQ-QUIC-CRT-0178` | Policy selects only a smaller legal prefix; payload, ordering, FIN, ownership, recovery, congestion, pacing, and completion authority remain unchanged. |
| Burst budget | `REQ-QUIC-CRT-0179` | Policy is a lower-only cap; congestion, pacing, anti-amplification, handshake, packet, endpoint, and retransmission budgets remain authoritative. |
| Oversized quantum | `REQ-QUIC-CRT-0180` | Admission decision is immutable for the logical write; byte identity, order, ownership, cancellation, disposal, continuation, and exactly-once completion remain authoritative. |

The parent trace set is:

- specification: `SPEC-QUIC-CRT-STAGE1-SEND-PATH`;
- architecture: `ARC-QUIC-CRT-0066`;
- work item: `WI-QUIC-CRT-0067`; and
- verification: `VER-QUIC-CRT-0068`.

Existing `REQ-QUIC-CRT-0175`, `REQ-QUIC-CRT-0176`,
`ARC-QUIC-CRT-0065`, `WI-QUIC-CRT-0066`, and
`VER-QUIC-CRT-0067` remain the application-send-turn-specific trace homes and
will relate to, not be replaced by, the unified Stage 1 set.

## Smallest Implementation Slices

1. Add compact common axis value, version, validity, latch, safety-override,
   decision, and outcome types plus the unified epoch schema and validator.
2. Adapt `application_send_turn_planning` into the common record without
   removing its v1 exporter; add deterministic construction joins and bounded
   publisher-loss provenance.
3. Add the batch-formation lower-only policy at the existing packet-plan
   boundary, with forced/observe/shadow modes and plan outcomes. Completed
   locally; focused Release build and requirement/scheduler tests are green.
4. Add the burst-budget lower-only policy where the runtime computes the
   existing 4/12 cap, with actor-turn latching and authoritative safety
   reduction.
5. Store the oversized admission policy and resolved quantum in the existing
   request completion, then expose forced/observe/shadow admission records and
   operation outcomes.
6. Export one unified raw row per bounded connection epoch, plus separate
   joined construction/plan/turn/operation records.
7. Add focused deterministic tests for every value, safety override, latch,
   fallback, lifecycle, cancellation, disposal, recovery, congestion, pacing,
   flow-control, ownership, terminal path, and force-legacy rollback.
8. Run a small correctness-only smoke. Require all four axis records, exactly
   one varied axis, adjacent applied `legacy_current`, exact forced/applied
   joins, behavior-neutral shadow, and append-only exclusions before any large
   campaign.

After that smoke, proceed to the roadmap's Stage 2 actor and memory
foundations before running another large matrix, normalized dataset transform,
or offline ML analysis. Stage 2 retains `actor_work_quantum`,
`buffer_copy_coalescing`, and explicitly reviewed conservative
`adaptive_backpressure`. Stages 3-5 remain queued in roadmap order:
`packet_flush_cadence` and `receive_delivery_quantum`; placement, platform,
datagram transport, and cross-architecture buffer/batching work; then the
separately governed congestion/pacing, ACK, crypto, and HTTP/3 QPACK profiles.

No item in this map authorizes `active_internal`, a production threshold,
online learning, or a large campaign.

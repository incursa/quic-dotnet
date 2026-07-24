---
title: "Adaptive Runtime Connection Observation Schema"
---

# Adaptive Runtime Connection Observation Schema

Status: unified Stage 1 four-axis runtime emission, materialization, semantic
validation, and the first correctness smoke are checkpointed; the Stage 2
actor-service observation and bounded epoch contracts are implemented without
a forceable actor policy or permanent Stage 1 join; broader correctness,
independent-host, and active-policy review remain open

The controller consumes one immutable, connection-local observation per
bounded epoch. Actor work updates primitive counters; snapshot construction
derives normalized values at an actor-safe boundary. No per-packet object,
dictionary, metric tag set, stream enumeration, or global lock is permitted.

This schema is an internal decision record and offline dataset source. It is
not a public metrics contract. Existing low-cardinality instruments in
[`../metrics.md`](../metrics.md) remain the operational metrics surface.

## Stage 1 Unified Epoch V1

The Stage 1 send-path library uses
[`../../schemas/adaptive-runtime-stage1-unified-epoch-v1.schema.json`](../../schemas/adaptive-runtime-stage1-unified-epoch-v1.schema.json)
for one bounded connection epoch containing exactly four axis records in this
order:

1. `application_send_turn_planning`;
2. `application_send_batch_formation`;
3. `queued_send_burst_budget`; and
4. `oversized_write_admission_quantum`.

Each record keeps its own observation, rule, snapshot, reason, and provenance
versions; validity flags; forced, shadow, selected, and applied identities;
bounded reason and safety override; decision boundary and latch; fallback
state; and explicitly scoped outcomes. Scenario, payload, and requested
concurrency are retained only under `workloadAnalysisOnly`, which is
permanently excluded from production features.

The permanent raw host first emits
[`../../schemas/adaptive-runtime-stage1-unified-epoch-raw-v1.schema.json`](../../schemas/adaptive-runtime-stage1-unified-epoch-raw-v1.schema.json).
A connection-local accumulator consumes all four seam-specific evidence sinks
and closes the summary at the existing connection epoch boundary. It retains
only bounded scalar values and counters. If an axis has no decision boundary
in an epoch, the raw record marks that axis `missing` and `unlatched`, reports
the configured forced and shadow identities, and leaves its event count and
outcomes at zero. It never invents an operation key, carries an earlier event
forward as fresh, or substitutes zero for an unavailable observation.

Construction, packet-plan, actor-turn, logical-write, and explicit
`epoch_summary` records remain
separate and validate against
[`../../schemas/adaptive-runtime-stage1-axis-decision-v1.schema.json`](../../schemas/adaptive-runtime-stage1-axis-decision-v1.schema.json).
The semantic validator
[`../../eng/adaptive-runtime/Test-AdaptiveRuntimeStage1UnifiedEvidence.ps1`](../../eng/adaptive-runtime/Test-AdaptiveRuntimeStage1UnifiedEvidence.ps1)
requires the deterministic campaign/run/cell/sample/connection/epoch/axis/
decision-sequence join, rejects duplicate or missing joins, permits at most one
forced axis per epoch, and requires every unforced adjacent axis to apply
`legacy_current`. Forced and applied values must match unless an explicit
safety override is recorded; shadow recommendations never change the applied
value.
An `epoch_summary` decision has null operation and plan keys. It is used only
for the unified per-epoch projection; it does not relabel or replace the
detailed construction, packet-plan, actor-turn, or logical-write source
record.

Observation ownership is independent from treatment ownership. A connection
may enable receive-credit, send-turn, and batch observation together so one
execution can populate contemporaneous axis records. At most one axis may have
a behavior-distinct forced treatment; every adjacent applied value remains
`legacy_current`. Observe-only and shadow modes therefore do not compete for a
single global ownership slot.

## Stage 2 Actor Service Observation V1

The behavior-neutral Stage 2 foundation uses
[`../../schemas/adaptive-runtime-actor-service-observation-v1.schema.json`](../../schemas/adaptive-runtime-actor-service-observation-v1.schema.json)
for one complete observed shard dispatch and
[`../../schemas/adaptive-runtime-actor-service-epoch-v1.schema.json`](../../schemas/adaptive-runtime-actor-service-epoch-v1.schema.json)
for its bounded connection-local aggregation. Each service record contains a
monotonic connection sequence; shard, wake, and wake-position identity; closed
work kind; enqueue delay; full transition-and-effect service duration; pending
work count; emitted-effect and existing follow-on counts; lifecycle phase;
completion disposition; and explicit validity flags. A guarded sink is
diagnostic-only and cannot affect progress or ownership.

The fixed-field accumulator retains closed work-kind, disposition, wake,
duration, effect, and follow-on counters plus totals, maxima, integer EWMAs,
and the union of validity flags. It has no dictionaries, stream scans, global
lock, or unbounded state. Queue delay is not relabeled as oldest shard-item
age, pending work count is not relabeled as runnable-connection count, and a
dequeued event is not relabeled as a reviewed useful work unit.

This v1 contract intentionally marks runnable-connection count, oldest shard
item age, deadline lateness, and useful work units unavailable. It does not
define policy values, forcing, shadow selection, or a latch for
`actor_work_quantum`; the applied shard behavior remains `legacy_current`.
The current Stage 1 epoch callback occurs before complete actor service, so
actor summaries are not silently inserted into that row. A later exact
post-service export boundary must define deterministic join keys and preserve
sample scope before permanent unified campaign emission.

## Epoch Envelope

| Field | Type and unit | Owner and update point | Cost and availability |
| --- | --- | --- | --- |
| `connection_epoch_sequence` | unsigned integer | Connection controller increments on snapshot | O(1), required |
| `epoch_start_ticks`, `epoch_end_ticks` | monotonic ticks | Connection actor | Two scalar reads, required |
| `active_duration_us` | integer microseconds | Derived from monotonic ticks | O(1), required |
| `observation_contract_version` | bounded string | Static controller metadata | Constant, required |
| `policy_rule_version` | bounded string | Static reviewed-rule metadata | Constant, required even in shadow |
| `advisor_age_us` | nullable integer microseconds | Derived from immutable runtime-advisor snapshot | O(1); null when absent |
| `missing_signal_mask` | unsigned bit mask | Snapshot builder | O(1); required |
| `stale_signal_mask` | unsigned bit mask | Snapshot builder | O(1); required |
| `lifecycle_flags` | bit mask | Existing connection lifecycle transitions | O(1); required |
| `has_issued_application_data` | boolean, monotonic false-to-true | `QuicConnectionRuntime` write configuration when a positive-length application write is admitted | Existing O(1) volatile write/read; required for receive-credit selector replay |

Wall-clock timestamps, peer addresses, connection IDs, stream IDs, URLs, and
benchmark labels do not enter the runtime observation. The offline row joins a
pseudonymous connection key and workload identity through the campaign
contract.

## Application-Send Turn Shadow V1 Subset

The implemented `application_send_turn_planning` runtime contract remains an
axis-specific record rather than reusing a receive-credit epoch. Its required
bounded signals are `queued_application_writes`, `outbound_backlog_bytes`,
`distinct_queued_send_streams`, `oldest_application_send_age_us`,
`queue_delay_ewma_us`, `actor_service_time_ewma_us`,
`burst_limit_hits_epoch`, `congestion_window_bytes`, `bytes_in_flight`,
`retained_send_buffers`, `retained_send_bytes`, and bounded lifecycle,
recovery, resource, missing, stale, saturation, contradiction, and
out-of-domain flags.

The first shadow rule may use only a reviewed subset of those fields, but every
required field's absence remains explicit and deterministically recommends
`conservative`. Optional values are never rewritten as zero. Snapshot
construction occurs at the existing application-send actor-turn planning
boundary, inspects at most 64 queued writes and 12 distinct stream identities,
and expires after one actor turn. A partial bounded scan is marked saturated
and falls back conservatively. Logical backlog bytes are derived from parsed
STREAM data length, while retained bytes record backing-buffer capacity; the
two values are not silently combined. Recovery probe sends bypass this
observation boundary and remain attributable only to recovery.
Receive-credit epochs remain attributable only to
`receive_credit_publication`.

The raw send-turn record is validated by
[`../../schemas/adaptive-runtime-application-send-turn-raw-v1.schema.json`](../../schemas/adaptive-runtime-application-send-turn-raw-v1.schema.json)
before standalone conversion. The resulting send-turn epoch interval begins at
one planning capture and ends at the next capture for the same connection. It
is evidence timing, not the one-turn policy latch lifetime and not a claim of
exact actor service duration. The final record has no following boundary, so
the exporter gives it the minimum positive schema duration and retains
`terminal_partial_epoch`; it is never analysis-clean. Signals not captured by
the axis-specific runtime record, including `has_issued_application_data`,
remain null rather than being fabricated as zero or false.

## Application-Send Batch Formation V1 Subset

The implemented `application_send_batch_formation` record is captured at the
existing packet-plan boundary after the runtime has computed the legal payload
and resource budget. Its closed values are `legacy_current` and
`single_eligible`. `legacy_current` retains the existing eligible-prefix count;
`single_eligible` may reduce that count to one but cannot select an ineligible
write, increase a payload budget, change priority or same-stream ordering, or
bypass FIN, ownership, flow-control, congestion, pacing, anti-amplification,
recovery, lifecycle, cancellation, disposal, queue, packet, or buffer guards.

The v1 observation retains a nonzero packet-plan sequence, monotonic capture
ticks, maximum legal payload bytes, legal eligible-write count and bytes,
bounded missing and stale masks, saturation/contradiction/out-of-domain
conditions, and lifecycle flags. The decision retains observation, rule,
snapshot, reason, and provenance versions; forced and shadow identities;
selected and applied values; selection source; bounded reason and safety
override; and a one-packet-plan latch. The outcome records the actual plan
kind, applied write count, whether queued data remains, and the authoritative
blocked reason. A failing evidence sink is swallowed and cannot change
transport completion.

The initial shadow rule is deliberately neutral for complete inputs:
`legacy_current` is recommended and applied. Invalid shadow inputs recommend
the conservative `single_eligible` value but still apply `legacy_current`.
Forced modes bypass selection only; a blocked, terminal, or disposed plan
records the safety override and leaves runtime authority unchanged.

## Queued-Send Burst Budget V1 Subset

The implemented `queued_send_burst_budget` record is captured once when the
runtime enters the existing recovery-progress queued-send service loop. Its
closed values are `legacy_current` and `single_datagram`. `legacy_current`
retains the legal cap computed by `QuicSendPolicy`; `single_datagram` may lower
an allowed cap to one but cannot turn a blocked budget into an allowed budget
or raise any congestion, pacing, anti-amplification, recovery, retransmission,
handshake, packet, endpoint, flow-control, queue, or buffer limit.

The actor-turn observation retains a nonzero turn sequence, monotonic capture
ticks, the legal and configured datagram caps, handshake state, bounded queue
count, logical backlog, stream diversity, oldest age, queue-delay and
actor-service EWMAs, prior burst-limit hits, congestion state, retained send
state, lifecycle flags, missing and stale masks, and bounded
saturated/contradictory/out-of-domain/recovery/resource conditions. The
decision retains observation, rule, snapshot, reason, and provenance versions;
forced and shadow identities; selected and applied values; selection source;
bounded reason and safety override; and a one-actor-turn latch.

The outcome records the legal and applied caps, emitted datagrams, queue counts
before and after service, authoritative recovery-flush outcome, and blocked
reason. The runtime recomputes the legal budget before every datagram and
applies the latched value only as a lower cap. A diagnostic sink exception is
swallowed and cannot affect transport work. The initial complete-input shadow
rule is neutral and recommends `legacy_current`; invalid shadow inputs retain
their explicit validity and conservative recommendation while applying
`legacy_current`. Forced values still pass every safety guard.

## Oversized-Write Admission Quantum V1 Subset

The implemented `oversized_write_admission_quantum` record is captured once at
logical-write admission for writes larger than the retained 32 KiB fragment
limit. Its closed values are `legacy_current`, `single_fragment`, and
`bounded_multi_fragment`. `legacy_current` preserves the exact retained
dispatcher-plus-16-through-24-observer selector. `single_fragment` uses the
retained conventional one-fragment request path. `bounded_multi_fragment`
selects the retained two-fragment actor-turn path, but a missing continuation
dispatcher or authoritative lifecycle, resource, contradiction, or
out-of-domain guard falls back to `single_fragment`. Recovery state remains
explicit evidence while the existing recovery path continues to govern work.

The admission observation retains a nonzero connection-local logical-write
sequence, monotonic capture ticks, logical and remaining bytes, current
application-payload and fragment limits, bounded observed-stream and queued
write counts, queue-delay and actor-service EWMAs, congestion state, retained
send state, dispatcher availability, the exact legacy-selected quantum, the
legal maximum quantum, lifecycle flags, missing and stale masks, and bounded
saturated, contradictory, out-of-domain, recovery, and resource conditions.
Logical-write length is a protocol-operation signal; scenario names, benchmark
payload labels or constants, requested concurrency, peers, URLs, and
application identity never enter the selector.

The resolved quantum is immutable for the operation and is stored with the
existing completion source for the multiplexed path or carried by the existing
async logical-write loop for the conventional path. Terminal evidence records
the applied quantum, committed fragments and bytes, continuation-post attempts,
completion latency, and one of `completed`, `canceled`, `terminal`, `disposed`,
`failed`, or `continuation_post_failed`. The evidence latch completes exactly
once. A sink failure is swallowed and cannot change transport completion.
Disabled and forced-without-observation execution skips observation capture
and preserves the retained selector cost shape.

The initial complete-input shadow rule is neutral and recommends
`legacy_current`; invalid shadow inputs recommend `single_fragment` while
still applying `legacy_current`. Missing or stale diagnostic signals remain
explicit but do not make a separately legal forced mechanism unforceable.
Forced modes never bypass the continuation-dispatcher, ownership, completion,
cancellation, disposal, terminal, recovery, congestion, pacing,
anti-amplification, flow-control, packet, queue, or buffer guards.

## Signal Inventory

Availability values are `existing`, `derivable`, or `new-counter`. A
`new-counter` is a future implementation requirement, not work begun by this
plan.

| Signal | Representation | Sampling owner | Update rule | Availability and expected cost |
| --- | --- | --- | --- | --- |
| `open_streams` | saturated `u16` count | Connection stream registry | Increment/decrement on open/retire | Derivable; O(1) transitions |
| `live_observer_streams` | saturated `u16` count | `QuicStreamObserverDirectory` | Existing add/remove count | Existing; volatile O(1) snapshot |
| `active_streams` | saturated `u16` count | Connection stream state | Transition count when a stream gains or loses active work | New-counter; O(1) transition |
| `runnable_streams` | saturated `u16` count | Application-send queue and receive-delivery queues | Transition count on empty/non-empty change | New-counter; O(1), no epoch enumeration |
| `receive_active_streams`, `send_active_streams` | saturated `u16` counts | Stream state and application-send queue | Directional empty/non-empty transitions | New-counter; O(1) |
| `inbound_bytes_epoch`, `outbound_bytes_epoch` | `u64` bytes | Existing receive and send commit points | Add committed bytes | Derivable; O(1) increments |
| `inbound_rate_ewma_bps`, `outbound_rate_ewma_bps` | `u64` bytes/second | Snapshot builder | Fixed-point EWMA from epoch deltas | New derived values; O(1) per epoch |
| `bytes_per_active_receive_stream`, `bytes_per_active_send_stream` | `u64` bytes | Snapshot builder | Saturating division; zero when denominator is zero | Derived; O(1) |
| `queued_application_writes` | saturated `u32` count | `QuicApplicationSendQueue` | Existing queue count | Existing; O(1) snapshot |
| `distinct_queued_send_streams` | saturated `u16` count | Application-send flush boundary | Reuse bounded distinct-stream observation | Existing when shadow diagnostics are active; bounded stack work |
| `oldest_application_send_age_us` | `u64` microseconds | Application-send queue | Earliest retained enqueue timestamp by bounded cause | Derivable from existing retention snapshot; coarse sample only |
| `queue_delay_ewma_us` | `u32` microseconds | `QuicApplicationSendPressureClassifier` | Existing integer EWMA | Existing, diagnostics-gated O(1) |
| `actor_service_time_ewma_us` | `u32` microseconds | Connection actor | Fixed-point update at work-item completion | New connection-local counter; existing metric is shard/work-item scoped |
| `queue_to_service_ratio_q16` | unsigned Q16.16 | Snapshot builder | `queue_delay / max(service, 1)` | Derived; O(1), machine-transferable |
| `actor_turns_epoch` | `u32` | Connection actor | Increment per processed connection work item | New-counter; O(1) |
| `useful_work_units_epoch` | `u32` | Existing commit points | Increment for committed bytes/operations using a fixed documented unit | New-counter; O(1); definition must be versioned |
| `follow_on_flush_items_epoch` | counts by bounded kind | Connection actor | Reuse application-send, flow-control, and stream-capacity flush counts | Existing metric source; add connection accumulator only if selected |
| `write_completion_ewma_us` | `u32` microseconds | Stream-action completion | Fixed-point update from existing completion timestamps | Derivable; existing histogram source |
| `connection_receive_headroom_bytes` | `u64` | Connection stream state | Snapshot of advertised limit minus received/accounted bytes | Derivable under stream-state lock at epoch boundary |
| `minimum_stream_receive_headroom_bytes` | `u64` | Stream state | Maintain minimum through relevant transitions, not epoch enumeration | New-counter; bounded update cost |
| `estimated_receive_exhaustion_us` | nullable `u64` | Snapshot builder | Headroom divided by inbound EWMA | Derived; null without a usable rate |
| `connection_credit_pending_bytes` | `u64` | Connection stream state | Existing pending credit | Existing in retained receive-credit slice |
| `maximum_stream_credit_pending_bytes` | `u64` | Stream state | Maintain bounded maximum on pending-credit updates | New-counter; avoid stream scan |
| `time_since_credit_publication_us` | `u64` | Credit publication path | Monotonic timestamp on publication | New-counter; O(1) |
| `connection_flow_blocked_us_epoch`, `stream_flow_blocked_us_epoch` | `u64` microseconds | Flow-control blocked/unblocked transitions | Accumulate monotonic durations | New-counter; O(1) transitions |
| `outbound_backlog_bytes` | `u64` logical remaining bytes | Application-send queue | Add admitted logical bytes and subtract committed/removed bytes, including partial raw-write progress | New-counter; existing retained-byte snapshots measure backing-buffer capacity and must not be used as this signal |
| `burst_limit_hits_epoch` | `u32` | Queued-send flush | Increment on existing burst-limit outcome | Derivable; O(1) |
| `packet_fill_ratio_q16` | Q16.16 | Packet accounting | Accumulate authorized payload and packet capacity | New-counter; O(1) per committed packet, snapshot outside hot path |
| `packets_per_logical_operation_q16` | Q16.16 | Request completion plus packet accounting | Epoch aggregate | New-counter; no per-operation object retained |
| `control_frame_ratio_q16` | Q16.16 | Packet accounting | Bounded frame-category counters | New-counter; update only where frame category is already known |
| `congestion_window_bytes`, `bytes_in_flight` | `u64` bytes | Send runtime recovery snapshot | Existing connection-safe snapshot | Existing/derivable; O(1) per epoch |
| `loss_events_epoch`, `retransmissions_epoch`, `pto_events_epoch` | `u32` counts | Recovery transitions | Increment existing event sites | Derivable from existing metrics/event sources |
| `ack_eliciting_sent_epoch`, `ack_frames_sent_epoch` | `u32` counts | Packet accounting | Increment committed packet/frame counts | New-counter; O(1) |
| `retained_send_buffers`, `retained_send_bytes` | `u32`, `u64` | Application-send retention snapshot | Existing sampled snapshot | Existing coarse sample |
| `retained_receive_buffers`, `retained_receive_bytes` | `u32`, `u64` | Stream-state retention snapshot | Existing sampled snapshot | Existing coarse sample |
| `runtime_cpu_pressure_q16` | Q16.16 | Optional runtime advisor | Immutable coarse process snapshot | Future advisor; absent is valid |
| `thread_pool_delay_us` | nullable `u64` | Optional runtime advisor | Coarse sampled snapshot | Future advisor |
| `managed_memory_pressure_q16` | Q16.16 | Optional runtime advisor | Coarse sampled snapshot | Future advisor |
| `socket_send_backlog_q16` | Q16.16 | Optional runtime advisor | Coarse sampled snapshot | Future advisor |

## Normalization And Arithmetic

Runtime rules use integer or fixed-point arithmetic with saturating operations.
They must not depend on floating-point platform differences. EWMA shift,
counter saturation, zero-denominator handling, and time-unit conversion are
part of the observation contract version.

Rates and ratios are computed only from committed work. Retransmitted bytes do
not count as new application throughput. Missing values remain missing; they
are not encoded as zero. Dataset exports may include raw counters and derived
values, but production rules may consume only the reviewed subset named by the
rule version.

## Sampling Ownership And Cadence

Actor work only updates counters. A threshold crossing may request one
coalesced evaluation at the next connection-safe actor boundary. While useful
work continues, a coarse periodic epoch prevents stale policy; 250-500 ms is
the initial experiment range, not a production constant. Quiescent connections
stop evaluation or use a heartbeat near five seconds. Shutdown cancels future
epochs.

An epoch snapshot must not enumerate all streams. Any signal that cannot be
maintained with bounded transition work is excluded until a bounded
approximation is designed and validated.

## Missing, Stale, And Out-Of-Domain Rules

The snapshot is out of domain when any required signal is missing or stale,
arithmetic saturates in a rule-relevant field, advisor data conflicts with
connection evidence, resource bounds are near exhaustion, recovery is
unstable, or the reviewed rule declares the observation outside its trained
and validated envelope.

Out-of-domain handling is deterministic: propose the conservative policy,
record a bounded reason code, and require fresh sustained evidence before any
later promotion. A missing advisor alone cannot prevent connection progress.

## Instrumentation Neutrality

Disabled observation must preserve the same runtime path and produce no
connection-epoch objects or exports. Shadow capture may use an internal
campaign sink, but must not add connection or stream identity as
`System.Diagnostics.Metrics` tags. Neutrality requires same-binary disabled vs
enabled evidence as described in the shadow verification plan.

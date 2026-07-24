---
title: "Adaptive Runtime Connection Observation Schema"
---

# Adaptive Runtime Connection Observation Schema

Status: receive-credit v1 and application-send turn runtime subset
implemented; send-turn raw-host export and standalone epoch conversion
implemented; permanent runner capture and result/checksum joins implemented;
campaign evidence pending

The controller consumes one immutable, connection-local observation per
bounded epoch. Actor work updates primitive counters; snapshot construction
derives normalized values at an actor-safe boundary. No per-packet object,
dictionary, metric tag set, stream enumeration, or global lock is permitted.

This schema is an internal decision record and offline dataset source. It is
not a public metrics contract. Existing low-cardinality instruments in
[`../metrics.md`](../metrics.md) remain the operational metrics surface.

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

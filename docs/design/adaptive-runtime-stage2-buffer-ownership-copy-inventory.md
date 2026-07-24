---
title: "Adaptive Runtime Stage 2 Buffer Ownership And Copy Inventory"
---

# Adaptive Runtime Stage 2 Buffer Ownership And Copy Inventory

Status: reviewed implementation inventory; first send-side observation
contract implemented;
`buffer_copy_coalescing` remains `legacy_current` and non-forceable

This inventory maps the current data lifetime before a buffer policy is
introduced. It complements
[`adaptive-runtime-stage2-actor-memory-foundation.md`](adaptive-runtime-stage2-actor-memory-foundation.md)
and the `buffer_copy_coalescing` section of
[`adaptive-runtime-policy-axis-roadmap.md`](adaptive-runtime-policy-axis-roadmap.md).
It does not authorize a new copy strategy, change an owner, or treat an
existing platform batching mechanism as a connection policy.

## Current Ownership Chains

| Stable path ID | Admission or construction point | Current copy or retention | Owner and terminal release | Policy disposition |
| --- | --- | --- | --- | --- |
| `application_write_request` | `StreamActionRequestCompletion.EnsureOwnedStreamData` after a flow-control-blocked write must be retried | Copies the application span and optional suffix into one pooled `StreamWriteRequest` array. A sufficiently large existing request buffer may be reused. | The completion owns the array until success, failure, cancellation, retry handoff, or disposal calls `ReleaseOwnedStreamData`. | First connection-local copy observation boundary. The ordinary synchronous path does not take this retry copy, and the caller's memory is never retained past its completion contract. |
| `oversized_raw_queue` | Oversized STREAM-frame admission in `QuicConnectionRuntime.Streams` | Copies the committed logical data into a `QueuedRawStreamData` array before queueing. | `QuicApplicationSendQueue` owns the array until replacement, selected completion, stream removal, cancellation, terminal clear, or disposal returns it. | Candidate admission boundary. Existing maximum payload, flow-control, queue, and continuation guards remain authoritative. |
| `formatted_stream_payload` | `TryBuildOutboundStreamPayload` | Formats STREAM metadata and copies one logical data span plus suffix into a padded pooled `FormattedStreamPayload` array. | Ownership transfers from `QuicBufferLease` to the send/queue path, then to packet protection or queue cleanup. | Candidate construction boundary only after exact downstream ownership is retained. |
| `combined_application_send` | Multi-write queued-send plan | Copies the already legal selected payload prefix into one pooled `CombinedApplicationSend` array. | The protected-packet path consumes or returns the array; the queue continues to own original payload arrays until commit/removal. | Primary bounded coalescing seam. It may combine only the existing legal selection and cannot widen a Stage 1 plan. |
| `outbound_packet_protection` | Packet protection after a legal packet plan | Produces a separate protected packet array. | Send tracking and endpoint handoff retain the owner until socket completion, rejection cleanup, ACK/loss retirement, retransmission transfer, or terminal cleanup. | Correctness-critical implementation detail. A policy cannot bypass packet-number, crypto, recovery, congestion, pacing, or amplification accounting. |
| `sent_packet_plaintext_retention` | `TrackApplicationRetransmissionSent` | Copies retransmittable plaintext into a pooled `SentPacketRetention` array even when packet bytes have another owner. | `QuicConnectionSendRuntime` owns it until ACK, loss transfer, send rollback, close, or disposal. | Observation required before any retention change. Recovery authority is not a copy-policy output. |
| `retransmission_plaintext_clone` | `QuicRetransmissionQueue.CloneOwnedPlaintext` | Copies retained plaintext into a pooled `Retransmission` array when ownership cannot be moved safely. | The retransmission queue owns it until resend transfer, ACK/abandonment, close, or disposal. | Observation required. Loss/recovery correctness can require the copy. |
| `endpoint_datagram_handoff` | Hosted `QuicConnectionSendDatagramUpdate` | Usually passes an owned protected-memory slice to the endpoint. Windows UDP segmentation can send a contiguous same-array run without another managed copy. | `ReleaseDatagramOwner` returns the protected array after observer/socket processing, including exceptional paths. | Capability and completion timing are outcomes, not production controller inputs. |
| `linux_sendmmsg_staging` | `QuicSocketSendBatch.SendWithNativeSendMmsg` | Allocates unmanaged storage and copies every payload and destination before `sendmmsg`; repeated `SendTo` fallback uses the managed span directly. | The batch method frees every allocated unmanaged block in `finally`. | Platform-specific transport mechanism; keep independent from connection selection until copy cost and partial-send semantics are attributable. |
| `inbound_datagram_lease` | `QuicConnectionEndpointHost` receive loop | Receives directly into a bounded ring buffer or an `ArrayPool` fallback and transfers that owner into the packet event. Borrowed packet slices do not own or return storage. | `QuicConnectionPacketReceivedEvent.ReleaseOwnedDatagramBuffer` returns exactly once after shard processing; shutdown drain also releases the event. | Receive storage remains outside the first send-path policy. Pool provenance is observable, but policy cannot reuse a returned slice. |
| `receive_segment` | `QuicConnectionStreamState.CreateBufferedSegment` | Copies out-of-order or retained STREAM bytes into a pooled segment, sometimes renting a larger continuation block for expected coalescing. | Stream state owns the segment until delivery/removal, reset, terminal clear, or disposal calls `BufferedSegment.Release`. | Separate receive-side candidate. `receive_delivery_quantum` and receive-credit policy remain frozen while this path is characterized. |
| `handshake_control_and_ack` | Handshake, ACK, control-frame, listener-response, and retry helpers | Uses explicit pooled owners and leases for protocol-critical construction, protection, and retention. | Each existing protocol owner has a dedicated success/failure/terminal return path. | Excluded from the first `buffer_copy_coalescing` force seam. A later protocol-sensitive design is required. |

The `QuicBufferPoolOwner` enum and process metrics already distinguish most
rent sites. They do not identify the connection, logical operation, segment
count, copy bytes, ownership transfer, completion age, or exact return.
`QuicReceiveBufferPool` additionally exposes ring/fallback rents, returns,
outstanding, peak, and double-return attempts, but its current diagnostics are
pool/process scoped.

## Existing Useful Connection-Local State

The runtime already owns several trustworthy primitives:

- application-send queue buffer count, retained capacity, and oldest enqueue
  time as maintained O(1) total state, plus queue-cause detail through the
  existing diagnostic scan;
- receive retained segment count and rented capacity;
- sent-packet and retransmission retained-owner count, capacity, and oldest
  sent time as maintained O(1) total state, plus sent-packet storage and
  packet-number-span detail through the existing diagnostic dictionary scan;
- request, packet-plan, actor-turn, and logical-write identities;
- packet protection, congestion, pacing, recovery, flow-control, endpoint,
  lifecycle, cancellation, and disposal outcomes; and
- exactly-once packet-event and datagram-owner release helpers.

The current sent-packet storage and packet-number-span snapshot still
enumerates a dictionary. It is acceptable for diagnostics already guarded by
metrics, but it is not a new per-dispatch policy input. Application-send,
sent-packet, and retransmission total retention state is now maintained at
existing ownership transitions. Remaining Stage 2 observation work must use
maintained state or another already bounded snapshot. It must not add an
unbounded scan to the actor or packet hot path.

## Proposed Observation Contract

The current behavior-neutral v2 contract extends the retained v1 send-side
contract with closed retransmission-clone and receive-segment values. It emits
and accumulates a compact copy operation with:

- `quic-buffer-copy-observation-v2`;
- monotonic connection-local operation sequence;
- one closed path ID from the inventory above;
- one closed operation and decision-boundary value;
- logical byte count and copied byte count;
- source segment count and destination segment count;
- requested capacity and actual retained capacity;
- a path-derived current ownership class without object identity;
- whether the path reused, copied, formatted, combined, retained, or cloned
  storage;
- construction, packet-plan, actor-turn, logical-write, or receive-operation
  join key when one honestly exists;
- safety-authoritative blocked or fallback reason;
- lifecycle, cancellation, disposal, terminal, loss, and recovery state;
- exact applied value `legacy_current`;
- explicit missing, stale, saturated, contradictory, and out-of-domain flags;
  and
- attributable completion, release, and retained-age outcomes when the
  operation owns those boundaries.

One copy record cannot claim an epoch-independent outcome that is actually
sample scoped. Process pool totals, managed allocation samples, platform
capability, workload identity, host identity, and requested concurrency stay
in analysis-only run provenance and are joined through deterministic keys.

The disabled path must not construct a record, allocate, scan, or take a
global lock. Observe-only publication must be guarded so sink failure cannot
change ownership or progress.

The v1 observation and epoch schemas remain immutable for retained evidence.
The v2 epoch adds fixed `retransmissionCloneCount`, `receiveSegmentCount`, and
`cloneCount` fields. Defining those values does not claim their runtime
producers are complete; producer coverage requires separate mechanism and
ownership verification.

## Future Axis Contract

The stable axis ID remains `buffer_copy_coalescing`. Its first closed policy
set should reserve:

- `legacy_current`;
- `memory_conservative`;
- `copy_small`;
- `segment_preserving`; and
- `coalesce_bounded`.

Only `legacy_current` is implemented today. `memory_conservative` must become
a distinct legal behavior before it can be forced; it cannot be an alias used
to fabricate counterfactual coverage. Platform-specific values require an
immutable capability identity and a conservative fallback.

The earliest defensible send-path decision boundary is after a Stage 1
planner has produced an already legal payload prefix and before the runtime
rents or fills the combined/formatted payload. The chosen owner, capacity,
segments, completion trigger, and return path latch for that memory's entire
lifetime. No later controller transition can reinterpret or replace it.

## Correctness Guards

Every future value remains subordinate to:

- exactly one owner and one terminal release;
- stable application-byte identity and order;
- same-stream ordering, priority, FIN, reset, and cancellation semantics;
- flow-control, stream-capacity, packet-size, queue, and hard buffer bounds;
- congestion, pacing, anti-amplification, ACK, loss, recovery, and probe
  authority;
- packet-number and protection commit;
- no use after return or return while crypto/kernel code references memory;
- no hidden unbounded coalescing or lifetime extension; and
- no extension of sensitive plaintext lifetime for performance.

Forced modes will bypass selection only. They will never bypass these guards.
Force-legacy rollback must independently prove the current copy, ownership,
and release chain.

## Missing Evidence And Next Slices

Before a forceable value is implemented:

1. extend the implemented connection-local copy-operation counters from the
   write-request, oversized raw queue, formatted payload, combined-send, and
   sent-retention points to retransmission clones and receive segments;
2. keep sent-packet storage and packet-number-span scans diagnostic-only unless
   a separately reviewed controller input justifies maintained bounded state;
3. define exact transfer and terminal-release correlation without retaining
   object identity in the dataset;
4. add ownership tests for admission failure, partial construction, blocked
   send, cancellation, disposal, reset, FIN, loss, retransmission, shutdown,
   and sink failure;
5. add permanent export only after the record can join to a completed
   post-service epoch without shifting attribution;
6. run manual or nightly mechanism-cost and allocation checks outside CI; and
7. review application-visible and memory-pressure behavior before designing
   conservative-only `adaptive_backpressure`.

No large campaign, dataset transform, offline model, shadow rule, or active
behavior is justified by this inventory alone.

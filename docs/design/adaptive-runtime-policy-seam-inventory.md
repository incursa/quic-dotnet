---
title: "Adaptive Runtime Policy Seam Inventory"
---

# Adaptive Runtime Policy Seam Inventory

Status: implementation inventory reconciled; send-turn observe-only, shadow,
raw-host export, and permanent-runner epoch joins implemented; batch formation
is internally forceable and observable at the packet-plan boundary; one local
send-turn shadow cell and one retained-negative observation-neutrality cell
executed; unified four-axis export, broader campaigns, and active policy
blocked

This inventory describes controls that already exist in the runtime and the
minimum seam work that would be required before a controller could observe or
force them. It does not authorize a new controller, change a default, or widen
an accepted policy.

## Frozen Starting Point

The current worktree inspection is recorded in
[`../adaptive-runtime-policy-planning.md`](../adaptive-runtime-policy-planning.md).
The accepted oversized-write quantum and sticky read-dominant receive-credit
rule remain retained runtime behavior. The behavior-neutral application-send
pressure classifier remains diagnostic only. Rejected receive-credit cadences
and active scheduler experiments remain negative evidence.

The receive-credit publication axis completed its evidence review on
2026-07-23 with a non-promoting `remain_legacy_current` decision. Its shadow
and forced-policy seams remain permanent rollback and counterfactual tools;
the accepted selector remains authoritative. The next permitted axis is
`application_send_turn_planning`. Its current planner seam is internally
forceable as `legacy_current` or `conservative` at connection construction and
remains independently injectable for tests and benchmarks. The proposed
`REQ-QUIC-CRT-0175` and `REQ-QUIC-CRT-0176` slice authorizes planning for
bounded observation, behavior-neutral shadow recommendation, axis-specific
provenance, replay, and force-legacy rollback. The current runtime remains
behavior-neutral: forced identities, observe-only/shadow capture, deterministic
recommendation, raw export, and permanent result/checksum joins are
implemented, while `legacy_current` remains authoritative. It must not gain
active selection or behavior-distinct policy output until its own
forced-campaign, observation, offline-analysis, shadow, and review gates are
complete.

## Non-Negotiable Authority

No policy seam may override packet-number allocation, packet protection, path
selection, congestion or pacing budgets, anti-amplification, ACK generation,
loss recovery, flow-control safety, stream ordering, cancellation, disposal,
terminal completion, or buffer ownership. Policy output is an input to the
existing correctness-critical runtime, never a second scheduler.

## Existing Seams

| Axis or surface | Current owner and location | Current behavior | Decision boundary and hot-path cost | Latched today | Forceable today | Planning disposition |
| --- | --- | --- | --- | --- | --- | --- |
| Receive-credit publication | `QuicConnectionRuntime.ShouldUseBatchedReceiveCreditPath`; `QuicStream.ReadAsync`; `QuicConnectionStreamState.TryReadStreamData` | Immediate credit is the conservative path. The retained rule uses half-window batching only with at least 16 live observers and no application-data write in the connection lifetime. | One volatile distinct-stream count and one sticky-write read before locked stream-state bookkeeping on each productive application read. No allocation is intended. | The application-write fallback is connection-lifetime sticky; publication state is retained until threshold or forced flush. | Unit and benchmark callers can pass `useBatchedReceiveCredit`; ordinary end-to-end campaigns cannot yet force `legacy_current`, `immediate`, or `read_dominant_batch` independently. | Frozen retained behavior. Add a test-only forced-policy input before controller migration. First shadow target; no widening. |
| Oversized-write admission quantum | `QuicConnectionRuntime.ShouldUseMultiplexedOversizedWritePath`; `QuicConnectionRuntime.Streams` | Two existing 32 KiB chunks may be admitted per actor turn only when 16-24 distinct stream observers exist at logical-write admission. | One distinct-stream count at admission; the selected path is carried by the request completion. | Yes, for the logical write, including fragmentation and completion ownership. | Focused tests can construct the path, but there is no explicit forced-policy campaign control. | Frozen accepted axis. Inventory only; not the first controller migration. |
| Application-send first-write selection and continuation | `IQuicApplicationSendTurnPlanner`; `QuicApplicationSendTurnShadowController`; listener factory; runtime constructor | Null or `QuicCurrentApplicationSendTurnPlanner` preserves the static priority/sequence scheduler. The internal `legacy_current` and `conservative` forced modes retain that behavior as distinct campaign identities. Observe-only and shadow modes capture bounded axis-specific evidence while always applying `legacy_current`; injected planners remain a separate test seam and are rejected by runtime shadow configuration. | Connection actor at an existing queued-send planning boundary. At most 64 queued writes and 12 distinct stream identities are observed; partial capture is saturated and conservatively classified. | A plan and immutable shadow snapshot apply to one actor turn; stream ordering checks remain authoritative. | Yes: forced construction identity and runtime disabled/observe-only/shadow identity are independently selectable. The permanent raw host keeps forced construction provenance and observe-only/shadow turn evidence in separate versioned record streams. Multiple implemented axes may be observed together, but a counterfactual treatment still varies at most one. The ProtocolLab package builder stamps the selected treatment identity into an immutable raw-QUIC package. | Runtime observation, deterministic recommendation, guarded sink, raw-host export, raw-to-epoch conversion, result/checksum joins, replay, null-planner rollback, one local shadow cell, and one retained-negative observation-neutrality cell are implemented under `SPEC-QUIC-CRT-SEND-TURN-SHADOW`. Broader neutrality, independent-host, full-suite, and rollback campaign verification remain open. Retained negative experiments must not be revived. No active selection. |
| Application-send batch formation | `QuicApplicationSendScheduler`; `QuicApplicationSendQueue.SelectQueuedApplicationSendBatchCount`; `QuicApplicationSendBatchPolicy`; connection options and listener option copy | `legacy_current` packs the existing eligible queued-write prefix within the runtime-computed payload budget. `single_eligible` shortens that already-legal prefix to one write. Raw stream data and fragmentation remain single selection. | Existing connection-actor packet-plan boundary after congestion, pacing, anti-amplification, recovery, flow-control, packet, queue, and buffer budgets are computed. The selector is O(1) after the existing bounded eligible-prefix scan and adds no per-plan collection. | Exactly one packet plan, including blocked and fragment plans. | Yes: `legacy_current` and `single_eligible` are independently forceable per connection; disabled, observe-only, and shadow evidence modes are available; listener-returned options preserve the mode and sink. | Runtime force, observation, neutral shadow recommendation, versioned decision, bounded fallback/safety reasons, guarded sink, deterministic replay, and force-legacy rollback are implemented under `REQ-QUIC-CRT-0178`. The applied value is lower-only and cannot expand the legal prefix. Unified epoch export, permanent campaign input, BenchmarkDotNet cost evidence, full Release, and multi-host verification remain open. No active selection. |
| Queued-send burst budget | `QuicSendPolicy`; `QuicConnectionRuntime.GetMaximumQueuedApplicationSendBurstDatagrams` | Four datagrams before handshake confirmation and twelve after, further bounded by congestion and anti-amplification. | O(1) budget computation at queued-send service. | Per actor turn. | `QuicSendPolicySnapshot` can force the cap in unit tests; runtime campaigns cannot force it independently. | Keep safety budgets authoritative. A policy may lower an allowed quantum but cannot exceed computed budgets. |
| Contiguous application-datagram batching | `IQuicApplicationDatagramBatchPolicy`; `QuicAdaptiveApplicationDatagramBatchPolicy`; endpoint host | Starts on the contiguous/segmented path, then one-way promotes to ordinary datagrams after repeated distinct-stream pressure. | One bounded distinct-stream count at batch construction; connection-lifetime policy object. | Promotion is one-way for the connection. | Yes through injected policy and constructor thresholds. | Existing adaptive precedent. Do not merge its state machine with the proposed controller without a separate compatibility decision. |
| Application-send pressure classification | `QuicApplicationSendPressureClassifier`; runtime queue-delay observation; metrics | Diagnostic sparse/cooperative/saturated classification from integer queue-delay EWMA, bounded distinct queued streams, burst exhaustion, and asymmetric hysteresis. It does not select work. | Diagnostics-gated timestamp capture plus O(1) integer update; bounded stack storage at an existing flush boundary. | Classifier state is connection-local; transient queue drains do not imply policy rollback. | Deterministically forceable in unit tests and replayable from observations. | Reuse as an observation source, not as a production controller or proof that a rejected planner should return. |
| Flow-credit event coalescing | `QuicConnectionRuntime.TryQueueFlowControlCreditUpdate` and pending-credit flush | Coalesces producer notifications while preserving the highest pending MAX_DATA and MAX_STREAM_DATA values. | Producer-side synchronization plus at most one posted flush event until drained. | Pending values survive until runtime drain. | Focused tests can force sequences; no alternate policy exists. | Correctness-supporting mechanism, not an adaptive axis. Controller output must not bypass it. |
| Peer stream-capacity release coalescing | `QuicConnectionRuntime.TryQueueStreamCapacityRelease` and pending-release flush | Coalesces generic release wakeups while retaining scheduled stream IDs. | Existing producer-to-actor handoff. | Until the pending set drains. | Focused tests only. | Not an adaptive axis. Preserve exact release semantics. |
| Ready-stream ordering and fairness | `QuicApplicationSendQueue` priority/sequence order plus planner validation | Priority first, stable sequence within priority, and no later write may pass an earlier write on the same stream. | Existing queue ordering and planning snapshot. | Per queued request ordering. | Planner tests can force legal and illegal selections. | A future fairness quantum may use the planner seam, but the invariants are not configurable. |
| Actor wake and maximum work per wake | `QuicConnectionRuntimeShard`, deadline scheduler, follow-on flushes | The shard inbox and inline follow-on flushes govern service. There is no stable connection-policy seam for a maximum-work quantum. | Actor loop; changing it can affect every connection on a shard. | No policy latch. | No. | Observe first. Do not add a controller output until ownership, cross-connection fairness, and wake cost have a separate design. |
| Packet flush cadence | Runtime routing/stream send paths under `QuicSendPolicy`, congestion, pacing, recovery, and packet protection | Flushes authorized work at existing safe points and prioritizes retransmission where required. | Correctness-critical packet path. | Packet construction and accounting commit as one authoritative operation. | Partially forceable only through low-level tests. | Not ready as an adaptive seam. Never delay required progress or exceed existing budgets. |
| Backpressure and retained-buffer bounds | Application-send queue, receive state, buffer pool, endpoint/socket send | Existing queues and owners have independent bounds and terminal cleanup. | Multiple producer and actor paths. | Ownership is latched until commit, cancellation, or disposal. | Individual bounds are testable; there is no unified policy seam. | Bounds remain hard limits. Adaptation may become more conservative before a bound but cannot raise it. |
| Runtime pressure advice | Existing `QuicMetrics` pressure snapshots are diagnostic; no advisor interface exists | Samples retained buffers, retransmissions, receive retention, and queue state when instruments are enabled. | Coarse metrics snapshot, not per packet. | Immutable sample only. | Metrics listeners can enable sampling; no deterministic advisor fixture exists. | Define an immutable optional snapshot interface later. Absence, staleness, and disablement must map to conservative behavior. |

## Required Seam Contract Before Activation

Every controller-managed axis must eventually expose the same internal
test-only contract:

- a stable axis ID and enumerated policy values;
- `legacy_current`, `conservative`, and each eligible candidate as distinct
  values, even when two initially produce the same result;
- a forced setting that bypasses selection but not correctness and resource
  guards;
- a shadow setting that records the proposed value while applying
  `legacy_current`;
- a policy snapshot version and reason code;
- a documented safe application boundary and latch lifetime;
- a baseline path that does not require observations or an advisor; and
- an explicit statement of whether the forced value is campaign-only,
  internal diagnostic, or eligible for later production use.

Forced settings must not be public API or support promises during the planning
period. They exist to create counterfactual evidence.

## Readiness Classification

Only receive-credit publication, oversized-write admission, application-send
planning, and application-datagram batching have concrete selectable seams.
Only the planner and datagram-batch interfaces are presently convenient to
force per connection. Actor quantum, packet cadence, and backpressure are
observation-only topics until separate designs establish safe boundaries.

No seam in this inventory is approved for new production adaptation.

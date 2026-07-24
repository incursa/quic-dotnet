---
title: "Adaptive Runtime Policy Seam Inventory"
---

# Adaptive Runtime Policy Seam Inventory

Status: implementation inventory reconciled; unified four-axis Stage 1 export,
materialization, and correctness smoke checkpointed; Stage 2 actor-service
observation, buffer-copy v3, and post-service unified-evidence contracts
implemented without a forceable actor quantum; broader campaigns, actor
fairness policy, memory policy, and active behavior remain blocked

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
| Oversized-write admission quantum | `QuicOversizedWriteAdmissionPolicy`; `QuicConnectionRuntime.ResolveOversizedWriteAdmission`; `QuicConnectionRuntime.Streams`; connection options and listener option copy | `legacy_current` retains the exact dispatcher-plus-16-through-24-observer selector. `single_fragment` uses the retained conventional one-fragment request path. `bounded_multi_fragment` uses the retained two-fragment actor-turn path whenever the continuation dispatcher guard permits it. | Disabled and forced-without-observation paths perform O(1) mode and retained-selector reads and do not capture evidence. Observe-only and shadow capture one bounded logical-write admission record; no per-packet injection, dictionary, allocation, global lock, or unbounded stream scan is added. | Yes. The resolved quantum is carried for the entire logical write through fragmentation, continuation, retry, cancellation, disposal, terminal completion, and exactly-once result publication. | Yes: all three values are independently forceable per connection; disabled, observe-only, and shadow modes are available; listener-returned options preserve the mode and sink. | Implemented under `REQ-QUIC-CRT-0180`: versioned admission observation and decision, explicit validity and safety reasons, dispatcher fallback, logical-write outcome counters, deterministic replay, adjacent-axis rejection, guarded sink, and force-legacy rollback. Unified epoch export, permanent campaign input, BenchmarkDotNet cost evidence, full Release, and multi-host verification remain open. No active selection. |
| Application-send first-write selection and continuation | `IQuicApplicationSendTurnPlanner`; `QuicApplicationSendTurnShadowController`; `QuicApplicationSendTurnStage1Policy`; listener factory; runtime constructor | Null or `QuicCurrentApplicationSendTurnPlanner` preserves the static priority/sequence scheduler. The internal `legacy_current` and `conservative` modes are independently forceable while observe-only or shadow evidence remains enabled. The common Stage 1 decision reports the actual forced/applied value separately from the neutral shadow recommendation; injected planners remain a separate test seam and are rejected by runtime shadow configuration. | Connection actor at an existing queued-send planning boundary. At most 64 queued writes and 12 distinct stream identities are observed; partial capture is saturated and conservatively classified. | A plan and immutable shadow snapshot apply to one actor turn; stream ordering checks remain authoritative. | Yes: every forced value composes with disabled, observe-only, and shadow evidence modes. The permanent raw host keeps forced construction provenance and observe-only/shadow turn evidence in separate versioned record streams. Multiple implemented axes may be observed together, but a counterfactual treatment still varies at most one. The ProtocolLab package builder stamps the selected treatment identity into an immutable raw-QUIC package. | Runtime observation, deterministic recommendation, common Stage 1 decision adaptation, guarded sink, raw-host export, raw-to-epoch conversion, result/checksum joins, replay, null-planner rollback, one local shadow cell, and one retained-negative observation-neutrality cell are implemented under `SPEC-QUIC-CRT-SEND-TURN-SHADOW`. Broader neutrality, independent-host, full-suite, and rollback campaign verification remain open. Retained negative experiments must not be revived. No active selection. |
| Application-send batch formation | `QuicApplicationSendScheduler`; `QuicApplicationSendQueue.SelectQueuedApplicationSendBatchCount`; `QuicApplicationSendBatchPolicy`; connection options and listener option copy | `legacy_current` packs the existing eligible queued-write prefix within the runtime-computed payload budget. `single_eligible` shortens that already-legal prefix to one write. Raw stream data and fragmentation remain single selection. | Existing connection-actor packet-plan boundary after congestion, pacing, anti-amplification, recovery, flow-control, packet, queue, and buffer budgets are computed. The selector is O(1) after the existing bounded eligible-prefix scan and adds no per-plan collection. | Exactly one packet plan, including blocked and fragment plans. | Yes: `legacy_current` and `single_eligible` are independently forceable per connection; disabled, observe-only, and shadow evidence modes are available; listener-returned options preserve the mode and sink. | Runtime force, observation, neutral shadow recommendation, versioned decision, bounded fallback/safety reasons, guarded sink, deterministic replay, and force-legacy rollback are implemented under `REQ-QUIC-CRT-0178`. The applied value is lower-only and cannot expand the legal prefix. Unified epoch export, permanent campaign input, BenchmarkDotNet cost evidence, full Release, and multi-host verification remain open. No active selection. |
| Queued-send burst budget | `QuicSendPolicy`; `QuicQueuedSendBurstPolicy`; `QuicConnectionRuntime.TryFlushPendingApplicationSendsAfterRecoveryProgress`; connection options and listener option copy | `legacy_current` retains the existing four-datagram pre-confirmation and twelve-datagram post-confirmation cap. `single_datagram` lowers an already-legal actor-turn budget to one datagram. Congestion, pacing, anti-amplification, recovery, retransmission, handshake, packet, endpoint, flow-control, queue, buffer, lifecycle, cancellation, and disposal authority remain unchanged. | O(1) lower-only cap after the existing legal budget computation. The bounded observation reuses the existing at-most-64-write and 12-stream snapshot only when observation is enabled; disabled and forced-without-observation paths allocate no evidence object or collection. | Exactly one queued-send recovery-progress actor turn. The resolved maximum remains fixed while each loop iteration recomputes the authoritative legal budget. | Yes: `legacy_current` and `single_datagram` are independently forceable per connection; disabled, observe-only, and shadow evidence modes are available; listener-returned options preserve the mode and sink. | Runtime force, observation, neutral shadow recommendation, versioned decision, bounded validity/fallback/safety reasons, legal/applied/emitted outcomes, guarded sink, deterministic replay, adjacent-axis rejection, and force-legacy rollback are implemented under `REQ-QUIC-CRT-0179`. Unified epoch export, permanent campaign input, BenchmarkDotNet cost evidence, full Release, and multi-host verification remain open. No active selection. |
| Contiguous application-datagram batching | `IQuicApplicationDatagramBatchPolicy`; `QuicAdaptiveApplicationDatagramBatchPolicy`; endpoint host | Starts on the contiguous/segmented path, then one-way promotes to ordinary datagrams after repeated distinct-stream pressure. | One bounded distinct-stream count at batch construction; connection-lifetime policy object. | Promotion is one-way for the connection. | Yes through injected policy and constructor thresholds. | Existing adaptive precedent. Do not merge its state machine with the proposed controller without a separate compatibility decision. |
| Application-send pressure classification | `QuicApplicationSendPressureClassifier`; runtime queue-delay observation; metrics | Diagnostic sparse/cooperative/saturated classification from integer queue-delay EWMA, bounded distinct queued streams, burst exhaustion, and asymmetric hysteresis. It does not select work. | Diagnostics-gated timestamp capture plus O(1) integer update; bounded stack storage at an existing flush boundary. | Classifier state is connection-local; transient queue drains do not imply policy rollback. | Deterministically forceable in unit tests and replayable from observations. | Reuse as an observation source, not as a production controller or proof that a rejected planner should return. |
| Flow-credit event coalescing | `QuicConnectionRuntime.TryQueueFlowControlCreditUpdate` and pending-credit flush | Coalesces producer notifications while preserving the highest pending MAX_DATA and MAX_STREAM_DATA values. | Producer-side synchronization plus at most one posted flush event until drained. | Pending values survive until runtime drain. | Focused tests can force sequences; no alternate policy exists. | Correctness-supporting mechanism, not an adaptive axis. Controller output must not bypass it. |
| Peer stream-capacity release coalescing | `QuicConnectionRuntime.TryQueueStreamCapacityRelease` and pending-release flush | Coalesces generic release wakeups while retaining scheduled stream IDs. | Existing producer-to-actor handoff. | Until the pending set drains. | Focused tests only. | Not an adaptive axis. Preserve exact release semantics. |
| Ready-stream ordering and fairness | `QuicApplicationSendQueue` priority/sequence order plus planner validation | Priority first, stable sequence within priority, and no later write may pass an earlier write on the same stream. | Existing queue ordering and planning snapshot. | Per queued request ordering. | Planner tests can force legal and illegal selections. | A future fairness quantum may use the planner seam, but the invariants are not configurable. |
| Actor wake and maximum work per wake | `QuicConnectionRuntimeShard`, `QuicActorServiceObservation`, `QuicActorServiceEpochAccumulator`, `QuicActorWorkFoundation`, `QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator`, deadline scheduler, follow-on flushes | The shard inbox and inline follow-on flushes still govern service. Disabled or observe-only mode records versioned connection-attributable dispatch, wake, queue-delay, full service-time, effect, follow-on, lifecycle, connection-local inter-service gap, scheduled timer lateness, exact posted-or-servicing connection-contender count at service start when valid, and bounded epoch evidence. `quic-actor-useful-work-vector-v1` preserves unlike dispatch components without inventing a scalar. A versioned post-service boundary joins Stage 1, actor, and buffer summaries only after actor publication and work-item resource release. The permanent raw host writes that joined record with one connection key and explicit export-failure evidence. Runnable-connection count, oldest shard item age, reviewed scalar useful-work units, and exact remaining work remain explicitly missing; inter-service gap is not relabeled as continuous runnable time and contender count is not relabeled as runnable state or fairness. | One behavior-neutral record after an existing complete transition-and-effect dispatch, then one bounded epoch callback after follow-on measurement and resource release when its interval is due. Scheduled timer work retains the exact due tick in inactive work-item storage without increasing the compact work-item size. A separate packed generation-token gate proves idle, posted, servicing, repost-requested, and stopped ownership transitions without a queue reference or scheduling callback. Guarded connection-local sinks and fixed-field accumulators add no dictionary, stream scan, model, global lock, or controller output. | Observation wake identity and epoch state are bounded. Scheduled deadline provenance lasts for one timer work item; inter-service gap is connection-local between observed service starts; contender count is a service-start sample and epoch aggregates are bounded. The repost primitive has an exact generation lifetime from sole enqueue ownership through exact begin and safe-boundary completion or fail-closed stop; it is not a policy latch and is not wired into the shard. | Observation plus an unconnected repost ownership primitive only. `actor_work_quantum` remains `legacy_current` and non-forceable. | Implemented observation/epoch v3, unified evidence/raw v4, actor raw v2, useful-work vector, and repost state-machine foundation under `REQ-QUIC-CRT-0181`, `REQ-QUIC-CRT-0183`, `REQ-QUIC-CRT-0184`, `REQ-QUIC-CRT-0186`, and `REQ-QUIC-CRT-0187`. Campaign provenance supplies exact run, binary, host, workload, command, classification, and checksum inventory. Do not add a controller output or wire reposting until exact remaining work, cooperative yield boundaries, runnable-state and complete-shard fairness, terminal drain, recovery, cancellation, disposal, and ownership have a separately reviewed design. |
| Packet flush cadence | Runtime routing/stream send paths under `QuicSendPolicy`, congestion, pacing, recovery, and packet protection | Flushes authorized work at existing safe points and prioritizes retransmission where required. | Correctness-critical packet path. | Packet construction and accounting commit as one authoritative operation. | Partially forceable only through low-level tests. | Not ready as an adaptive seam. Never delay required progress or exceed existing budgets. |
| Buffer copy and coalescing | `StreamActionRequestCompletion`, `QuicApplicationSendQueue`, `QuicConnectionRuntime.Streams`, `QuicConnectionSendRuntime`, `QuicRetransmissionQueue`, `QuicConnectionStreamState`, endpoint hosts, `QuicBufferPool`, and `QuicReceiveBufferPool` | Application retry copies, raw queued data, formatted/combined payloads, protected packets, sent plaintext, retransmissions, and receive segments use distinct pooled owners and explicit release paths. The observe-only v3 contract covers all eight closed managed construction paths, including one-token protected-packet ownership across recovery and hosted endpoint handoff, with versioned connection-local records and fixed-field aggregation. Shared hosted segmentation records one owner rather than one record per slice. The application-send queue now maintains total retained count, capacity, and oldest enqueue time across every enqueue, replacement, removal, transfer, and clear. | Multiple admission, packet-plan, protection, recovery, endpoint, and receive-retention boundaries. Maintained total snapshots add no read-side scan; queue-cause detail, sent-packet storage, and retransmission detail may still scan. Copy-scope pool outstanding, Linux unmanaged staging, and independently verified kernel-send outcome remain missing or separate. | Yes for each correlated managed buffer lifetime: ownership, capacity, completion trigger, and return path remain fixed until terminal release. There is no policy transition. | Observation only. `legacy_current` is the sole real value; force and shadow identities remain null. | The reviewed ownership inventory and current release checkpoints are in `adaptive-runtime-stage2-buffer-ownership-copy-inventory.md` under `REQ-QUIC-CRT-0182` and `REQ-QUIC-CRT-0185`. Managed-owner correlation is complete; define and verify a distinct conservative implementation before forcing. Do not silently call an existing mechanism a counterfactual policy. |
| Backpressure and retained-buffer bounds | Application-send queue, receive state, buffer pool, endpoint/socket send | Existing queues and owners have independent bounds and terminal cleanup. | Multiple producer and actor paths. | Ownership is latched until commit, cancellation, or disposal. | Individual bounds are testable; there is no unified policy seam. | Bounds remain hard limits. Adaptation may become more conservative before a bound but cannot raise it. |
| Runtime pressure advice | Existing `QuicMetrics` pressure snapshots are diagnostic; no advisor interface exists | Samples retained buffers, retransmissions, receive retention, and queue state when instruments are enabled. | Coarse metrics snapshot, not per packet. | Immutable sample only. | Metrics listeners can enable sampling; no deterministic advisor fixture exists. | Define an immutable optional snapshot interface later. Absence, staleness, and disablement must map to conservative behavior. |

The actor seam's permanent evidence refinement retains every observation-v3
dispatch as an actor raw-v2 sample-scoped record in addition to the unified
epoch summary. Export validation joins only by source-scoped
`connectionKey + serviceSequence` membership in the inclusive summary range;
missing, duplicate, orphan, out-of-order, and bounded-channel-failed records
are invalid contract evidence. This does not add a policy value, controller
input, runnable-state claim, or scheduling behavior.

`REQ-QUIC-CRT-0187` now maintains exact shard-wide accounting for connections
with one or more accepted posted-or-servicing work items. Multiple work items
for the same connection coalesce into one contender; rejection, post-service
completion, resource release, and shutdown drain close the count. The
acceptance bit reuses compact work-item flag storage, so the layout remains
144 bytes. Actor observation v3 emits the exact count at service start when
valid; epoch v3 aggregates coverage, maximum, and count-above-one turns.
Missing, invalid, and saturated state is explicit. This is not a runnable,
starvation, fairness, or controller signal.

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

Receive-credit publication and the four Stage 1 send-path axes have concrete
internal counterfactual seams, while application-datagram batching remains a
separate retained adaptive precedent. Actor service now has a versioned
observation-only seam, but actor quantum, packet cadence, buffer coalescing,
and backpressure remain non-forceable until separate designs establish safe
boundaries.

No seam in this inventory is approved for new production adaptation.

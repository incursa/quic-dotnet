---
title: "Adaptive Runtime Controller State Machine"
---

# Adaptive Runtime Controller State Machine

Status: receive-credit, all four Stage 1 send-path axes,
`buffer_copy_coalescing`, `adaptive_backpressure`, and
`packet_flush_cadence`, `receive_delivery_quantum`, and
`connection_shard_placement`, and `application_datagram_batch_transport`
force/observe/shadow runtimes implemented;
measurement and broader campaign verification frozen; actor and fairness
axes remain blocked on reviewed safe mechanisms; active policy blocked

The controller is a deterministic connection-local selector evaluated only at
actor-safe boundaries. It publishes a compact immutable policy snapshot. It
does not own queues, streams, packets, recovery, timers, or buffers.

## Operating Modes

Operating mode is selected internally before connection creation and is not a
public API during the first implementation period.

| Mode | Applied behavior | Recorded behavior |
| --- | --- | --- |
| `legacy_current` | Existing selectors at commit `1b2611e1` remain authoritative | Optional bounded diagnostics only |
| `baseline_only` | Conservative values are forced for controller-managed axes | Reason `forced_baseline` |
| `observe_only` | `legacy_current` remains authoritative and no controller rule is evaluated | Versioned connection observations only |
| `shadow` | `legacy_current` remains authoritative | Controller state, proposed snapshot, and reasons are recorded |
| `active_internal` | Reviewed controller output is applied at safe boundaries | Applied and shadow snapshots are recorded |

No production implementation or activation is authorized by this document.
The first proposed migration is receive-credit publication. Its shadow phase
must reproduce the frozen legacy selector before any active behavior is
considered.

The implemented `application_send_turn_planning` shadow extension reuses the
state and fallback vocabulary but emits an axis-specific recommendation at the
existing application-send actor-turn planning boundary. The recommendation
has no planner consumer and the snapshot expires after one actor turn. Its
common Stage 1 decision separately records a forced value, when present, and
the neutral shadow recommendation. Thus a forced `conservative`
counterfactual may be observed or shadowed without misreporting its actual
applied value, while an unforced shadow execution still applies
`legacy_current`. The initial closed set is `legacy_current` and
`conservative`. Observe-only and shadow configuration is connection-local.
Multiple implemented axes may observe or shadow-recommend in the same
connection so unified epochs retain contemporaneous evidence. Treatment
ownership remains singular: at most one axis may be forced to a
behavior-distinct value and every adjacent applied value remains
`legacy_current`.

The implemented `application_send_batch_formation` selector resolves
`legacy_current` or `single_eligible` after the correctness-critical runtime
has produced an already-legal eligible prefix. Its snapshot and decision latch
for exactly one packet plan. Observe-only records the legacy decision; shadow
may recommend but never applies a new value; forcing can only shorten the
prefix and cannot bypass a blocked, terminal, disposed, or otherwise
authoritative runtime plan.

The implemented `queued_send_burst_budget` selector resolves `legacy_current`
or `single_datagram` after `QuicSendPolicy` has computed the legal
recovery-progress service budget. Its snapshot and cap latch for exactly one
actor turn. The correctness-critical loop recomputes congestion, pacing,
anti-amplification, recovery, retransmission, handshake, packet, endpoint, and
resource authority before every datagram, then applies the latch only as a
lower cap. Observe-only and shadow keep `legacy_current` applied. A forced
single-datagram treatment requires receive credit, send-turn planning, and
batch formation to remain `legacy_current`, and it cannot convert a blocked
budget into progress.

The implemented `oversized_write_admission_quantum` selector resolves
`legacy_current`, `single_fragment`, or `bounded_multi_fragment` once at
logical-write admission. `legacy_current` retains the exact dispatcher and
16-through-24-observer selector. The explicit values select the existing
single-fragment or accepted two-fragment mechanisms, while the continuation
dispatcher and all lifecycle, recovery, ownership, completion, congestion,
pacing, flow-control, packet, queue, and buffer guards remain authoritative.
The decision is carried unchanged until the logical write completes, is
canceled, is disposed, reaches terminal state, or fails.

The implemented `buffer_copy_coalescing` selector resolves `legacy_current`
or `memory_conservative` after Stage 1 has produced an already legal combined
send prefix and before the combined owner is rented and filled.
`legacy_current` preserves the exact prefix. `memory_conservative` is a
lower-only cap of two source segments, the smallest distinct coalesced
construction, and is not a performance-derived threshold. The decision
cannot widen or reorder the prefix or bypass priority, same-stream order,
FIN/reset/cancellation, flow control, stream capacity, packet size,
congestion, pacing, anti-amplification, recovery, packet protection, ownership,
or terminal release. Shadow recommends while applying legacy; invalid,
missing, stale, saturated, contradictory, out-of-domain, or lifecycle state
falls back to legacy even under forcing.

The implemented `adaptive_backpressure` selector resolves `legacy_current`
or `early_delay` exactly once for a new application admission before stream
reservation or owner admission. `legacy_current` continues immediately.
`early_delay` posts one continuation and adds at most one dispatcher/actor
turn only when a previously admitted application-send operation remains
queued. The continuation is posted immediately and the policy is not
reevaluated, so it never waits for an ACK, credit, congestion, pacing, socket,
or peer event. It cannot reject the operation, raise a hard limit, change
already-admitted ownership, or create a policy failure. Cancellation,
disposal, terminal state, invalid or contradictory observations, unavailable
continuation posting, and existing queue, buffer, stream, flow-control,
congestion, pacing, recovery, and ownership guards remain authoritative even
when `early_delay` is forced. A removed or completed admission makes the
posted continuation a no-op. Shadow recommends `early_delay` while applying
`legacy_current`; the latch expires after that one application admission.

The implemented `packet_flush_cadence` selector resolves `legacy_current` or
`prompt` at the existing optional small-application-write delay boundary.
The boundary is reached only after stream reservation and payload
construction have produced an eligible application write smaller than 32
bytes and before packet protection. `legacy_current` retains the existing
one-millisecond generation-checked lifecycle delay. `prompt` removes only
that optional delay and continues through the unchanged direct-send packet
protection and accounting path. The latch covers one logical-write packet
opportunity. Retransmission priority, address validation and amplification,
lifecycle, congestion, pacing, flow control, packet size and protection,
recovery, cancellation, terminal state, and ownership remain authoritative
under forcing. Observe-only applies legacy, and shadow recommends `prompt`
while applying legacy.

The implemented `receive_delivery_quantum` selector resolves
`legacy_current` or `single_segment` at the existing productive
application-read copy loop after cancellation, terminal, and zero-buffer
handling. `legacy_current` preserves copying from every contiguous source
segment that fits the caller buffer. `single_segment` stops after the first
productive source segment and returns a legal short read. The latch covers one
application read call. `receive_credit_publication` remains
`legacy_current`, and the existing batched-credit choice passes through
unchanged. Ordering, buffer ownership/release, FIN, reset, close,
cancellation, disposal, flow-control progress, congestion, pacing, recovery,
packet limits, and terminal behavior remain authoritative under forcing.
Observe-only applies legacy, shadow recommends `single_segment` while
applying legacy, and invalid or lifecycle input falls back to legacy.

The implemented `connection_shard_placement` selector resolves
`legacy_current` or `bounded_power_of_two_choices` exactly once during
connection registration. `legacy_current` retains sequential-handle modulo
shard-count assignment. The bounded choice compares that legacy shard with
one deterministic distinct alternate, reads only those two active-connection
counters, chooses the lower count, and uses the legacy shard as the tie break.
The route stores the applied shard and decision for the connection lifetime;
later load changes cannot migrate it. Failed route or runtime ownership
registration rolls back the selected counter, and unregister decrements the
stored route. Valid shard ownership, lifecycle, endpoint and packet routing,
timers, shutdown, congestion, pacing, recovery, flow control, packet, queue,
and buffer limits remain authoritative. Observe-only applies legacy; shadow
records the bounded choice while applying legacy; invalid, missing, stale,
saturated, contradictory, out-of-domain, lifecycle, and single-shard state
falls back to legacy even under forcing.

The implemented `application_datagram_batch_transport` selector resolves
`legacy_current`, `segmented_batch`, or `ordinary_datagrams` at each existing
application-send turn before optional contiguous batch-owner construction.
`legacy_current` preserves the capable server segmented path and the client
one-way promotion to ordinary datagrams after the retained sustained
distinct-stream pressure. `segmented_batch` can build a contiguous batch only
while the current socket capability epoch reports Windows
`UDP_SEND_MSG_SIZE`; `ordinary_datagrams` never builds that owner. The
configured snapshot is connection-lifetime, the client promotion latch is
one-way, and socket recreation publishes a new monotonic capability epoch.
Platform, address-family, probe, custom-sender, source-address, ECN,
packet-size, partial-send, endpoint, ownership, cancellation, disposal,
shutdown, recovery, congestion, pacing, flow-control, queue, and buffer
authority remain outside the selector and cannot be bypassed. Observe-only
applies legacy; shadow recommends ordinary datagrams while applying legacy;
unsupported capability, invalid observation, or lifecycle state falls back to
ordinary datagrams even when segmented batching is forced.

## States

| State | Meaning | Applied policy in `active_internal` |
| --- | --- | --- |
| `quiescent` | No useful connection work; active evaluation is stopped | Retain current safe snapshot; no promotion |
| `conservative` | Baseline or insufficient evidence | Conservative snapshot |
| `promotion_pending` | Candidate evidence is present but entry count or minimum dwell is incomplete | Conservative snapshot |
| `candidate` | Sustained in-domain evidence satisfies the reviewed entry rule | Candidate snapshot, only for new work |
| `demotion_pending` | Relief, contradiction, or degradation is present but normal exit confirmation is incomplete | Current candidate for already admitted work; new-work behavior follows the axis contract |
| `fallback` | Missing, stale, out-of-domain, resource, recovery, or progress evidence requires immediate conservatism | Conservative snapshot for new work; correctness bypasses policy immediately |
| `terminal` | Shutdown, disposal, or terminal close has begun | No new policy decisions |

`fallback` is not an error-recovery scheduler. It only prevents a candidate
from governing new work. Existing runtime terminal and recovery paths remain
authoritative.

## Transition Table

| From | Condition at an actor-safe evaluation | To | Reason code |
| --- | --- | --- | --- |
| `quiescent` | Useful work resumes with a complete observation | `conservative` | `activity_resumed` |
| `conservative` | Candidate entry predicate is true for one epoch | `promotion_pending` | `candidate_observed` |
| `promotion_pending` | Entry predicate remains true for the required consecutive epochs and conservative dwell has elapsed | `candidate` | `promotion_sustained` |
| `promotion_pending` | Entry predicate clears or contradicts | `conservative` | `promotion_evidence_cleared` |
| `candidate` | Normal leave predicate is true for one epoch | `demotion_pending` | `relief_observed` |
| `demotion_pending` | Leave predicate remains true for the required consecutive epochs and candidate dwell has elapsed | `conservative` | `demotion_sustained` |
| `demotion_pending` | Candidate predicate becomes stable again | `candidate` | `relief_cleared` |
| Any nonterminal | Required signal is missing/stale, observation is out of domain, arithmetic saturates, contradictory regime evidence persists, or an independent resource/recovery guard fires | `fallback` | Bounded guard-specific code |
| `fallback` | All guards clear and fresh complete evidence persists for the fallback recovery count | `conservative` | `fallback_recovered` |
| Any nonterminal | Connection becomes inactive without pending correctness work | `quiescent` | `connection_quiescent` |
| Any nonterminal | Shutdown, disposal, or terminal close begins | `terminal` | `terminal_started` |

Fallback reason codes are a closed set: `missing_signal`, `stale_signal`,
`out_of_domain`, `contradictory_signals`, `resource_guard`, `recovery_guard`,
`flow_progress_guard`, `cancellation_or_disposal`, `shutdown`,
`rule_version_mismatch`, and `arithmetic_saturated`.

## Hysteresis And Dwell Contract

Each rule version defines separate entry and leave predicates, consecutive
epoch counts, minimum conservative dwell, minimum candidate dwell, fallback
recovery count, and maximum observation age. Entry and leave thresholds may
not be the same. Rule changes reset pending evidence and return new work to the
conservative snapshot.

Counts and dwell are evaluated from monotonic time and epoch sequence. A
delayed epoch cannot be replayed as multiple confirmations. Out-of-order or
duplicate epochs are rejected deterministically.

## Safe Application And Latching

Every published policy snapshot contains `snapshot_version`, `rule_version`,
`state`, `epoch_sequence`, axis values, and transition reason. Consumers read
one snapshot and latch only the axes relevant to the admitted operation.

- A logical write latches admission quantum, fragmentation, completion, and
  ownership behavior for its lifetime.
- A packet plan latches only until packet construction either commits or is
  abandoned without externally visible state.
- A buffer-coalescing decision latches from the post-Stage 1 combined-send
  boundary through the resulting owner's existing exactly-once terminal
  lifetime.
- A receive-credit read may use the current safe publication value, but
  pending credit is never discarded on a transition and required progress
  always bypasses batching.
- Stream ordering, cancellation, disposal, FIN, reset, and shutdown bypass a
  policy when needed to preserve correctness and progress.

A new snapshot never mutates an in-flight operation's ownership contract.

## Sticky Facts

Connection-lifetime facts are monotonic inputs, not controller states. For the
first proposed receive-credit migration, `has_issued_application_data` changes
only from false to true. Once true, the candidate read-dominant batching value
is ineligible for the remainder of that connection, regardless of later queue
shape. The controller cannot clear the fact or infer that duplex activity has
ended.

This preserves the retained sticky duplex guardrail and prevents the rejected
half-window and quarter-window policies from reactivating.

## Immediate Progress Guards

The following conditions bypass cadence and force required work immediately:

- receive credit approaches exhaustion or a peer reports blocking;
- a receive limit is near numeric saturation;
- terminal read, FIN, reset, shutdown, cancellation, or disposal needs credit
  or completion progress;
- recovery requires an authorized probe or retransmission;
- an existing hard queue or buffer bound is approached; or
- the controller is unavailable, or a rule-required input is absent, disabled,
  incompatible, or stale. An optional advisor's absence is recorded but does
  not by itself make a rule ineligible.

These guards cannot be weakened by forced campaign settings.

## Determinism

Production rules are reviewed code or immutable rule tables using integer and
fixed-point arithmetic. Evaluation order, tie breaking, missing-value behavior,
saturation, and reason precedence are versioned. Given the same ordered
observations, lifecycle facts, and rule version, replay must produce identical
states, snapshots, and reasons.

Offline machine learning may identify regimes and candidate thresholds. It
does not execute in this state machine, update production thresholds, explore
policies, or receive benchmark labels as runtime inputs.

## First Migration Boundary

The first proposed migration is deliberately semantic-neutral:

1. Express `legacy_current`, `immediate`, and the frozen
   `read_dominant_batch` receive-credit values as distinct internal forced
   settings.
2. Run the controller in shadow while `legacy_current` remains applied.
3. Prove that the shadow proposal exactly reproduces every legacy selector
   decision and sticky fallback across deterministic replays and matched local
   runs.
4. Review the evidence and the canonical CRT requirement slice.
5. Only a later explicitly approved slice may apply controller output.

No broader receive-credit rule is part of this migration boundary.

## Decisions Left For Review

This planning bundle intentionally does not settle whether the first epoch
basis is wall-clock, RTT-normalized, or work-normalized; whether one unified
policy snapshot type is preferable to seam-local selectors; or whether the
optional runtime advisor is present in v1. The permanent campaign must compare
cadence bases before constants are fixed. The first active slice, if approved,
is limited to one axis regardless of those later choices.

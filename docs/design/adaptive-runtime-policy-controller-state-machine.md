---
title: "Adaptive Runtime Controller State Machine"
---

# Adaptive Runtime Controller State Machine

Status: receive-credit and application-send turn shadow runtimes implemented;
send-turn raw-host export implemented; dataset and campaign verification
pending; active policy blocked

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
state and fallback vocabulary but emits an
axis-specific recommendation at the existing application-send actor-turn
planning boundary. `legacy_current` remains applied, the recommendation has no
planner consumer, and the snapshot expires after one actor turn. The initial
closed recommendation set is `legacy_current` and `conservative`; both retain
the current legal planner behavior until a later behavior-distinct proposal
has its own reviewed requirement and evidence package. Observe-only and shadow
configuration is connection-local, rejects simultaneous shadow ownership by
another axis, and requires adjacent receive-credit behavior to remain
`legacy_current`.

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

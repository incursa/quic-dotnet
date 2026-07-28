---
title: "Adaptive Runtime Policy Axis Roadmap"
---

# Adaptive Runtime Policy Axis Roadmap

Status: user-approved direction for staged planning and measurement
implementation; active policy review required

## Purpose

This document defines the long-term portfolio of adaptive and swappable
runtime policy axes for `quic-dotnet`. It is intentionally broader than the
first receive-credit controller migration. It tells future Codex work which
runtime decisions are promising performance controls, which decisions are
correctness mechanisms rather than policy axes, what must be measured, where a
decision can safely take effect, and what evidence is required before an axis
can progress.

This roadmap does not authorize production implementation, activation,
benchmark-driven threshold changes, online learning, or concurrent widening
of multiple policy axes. The existing planning and verification bundle remains
authoritative:

1. [`adaptive-runtime-policy-seam-inventory.md`](adaptive-runtime-policy-seam-inventory.md)
2. [`adaptive-runtime-policy-observation-schema.md`](adaptive-runtime-policy-observation-schema.md)
3. [`adaptive-runtime-policy-controller-state-machine.md`](adaptive-runtime-policy-controller-state-machine.md)
4. [`../protocol-lab/adaptive-runtime-policy-local-campaign.md`](../protocol-lab/adaptive-runtime-policy-local-campaign.md)
5. [`../protocol-lab/adaptive-runtime-policy-dataset-provenance-contract.md`](../protocol-lab/adaptive-runtime-policy-dataset-provenance-contract.md)
6. [`../testing/adaptive-runtime-policy-shadow-verification.md`](../testing/adaptive-runtime-policy-shadow-verification.md)
7. [`../testing/adaptive-runtime-policy-acceptance-rollback.md`](../testing/adaptive-runtime-policy-acceptance-rollback.md)

The current checkpoint and retained negative evidence remain documented in
[`../adaptive-runtime-policy-planning.md`](../adaptive-runtime-policy-planning.md)
and the adaptive-runtime campaign evidence records.

## Executive Direction

The runtime should not be redesigned as a collection of unrelated schedulers.
It should remain one stable, correctness-critical engine with independently
selectable policy axes at already safe decision boundaries.

The intended architecture is:

- one authoritative connection actor and protocol state machine;
- one immutable, versioned connection observation per bounded epoch;
- one deterministic controller state machine;
- one immutable policy snapshot containing independently versioned axis
  selections;
- seam-local consumers that latch only the decisions needed by newly admitted
  work;
- forced modes for counterfactual campaigns;
- shadow modes that propose without applying;
- hard progress, ownership, congestion, recovery, and resource guards that
  cannot be overridden by a policy;
- offline machine learning for regime discovery and rule derivation; and
- reviewed integer or fixed-point rules in production, never online
  exploration.

The principal design objective is not to find one implementation that wins
every benchmark. The objective is to preserve multiple correct implementations
of decisions that have genuine workload-dependent tradeoffs, measure their
outcomes, discover transferable operating regimes offline, and apply reviewed
deterministic rules conservatively.

## Terminology

### Runtime mechanism

A runtime mechanism owns correctness and progress. Examples include stream
ordering, MAX_STREAMS release, packet-number allocation, packet protection,
loss detection, retransmission accounting, cancellation, disposal, and buffer
ownership. A policy may choose among legal inputs to a mechanism; it may not
replace or bypass the mechanism.

### Policy axis

A policy axis is one bounded decision with:

- a stable axis ID;
- a conservative value;
- one or more correct candidate values;
- a documented decision boundary;
- a latch lifetime;
- a forced campaign setting;
- a shadow proposal;
- bounded observations and reasons;
- explicit fallback behavior; and
- independent acceptance and rollback evidence.

### Policy implementation

A policy implementation is one named value on an axis. It is not necessarily
a separate class. A constant, rule table, injected strategy, or bounded enum
may be sufficient when it preserves a stable seam.

### Controller

The controller selects policy values. It does not own work queues, packets,
streams, timers, or buffers. Its output is advisory until a seam-local
correctness mechanism validates and applies it.

### Runtime advisor

The optional runtime advisor provides coarse host or process pressure
observations. It is not a controller and not a policy axis. Its absence,
staleness, or disablement must remain valid and must select conservative
behavior when a rule requires it.

## Non-Negotiable Invariants

No policy axis may:

- change packet-number uniqueness or allocation order;
- bypass packet protection or authenticated encryption;
- exceed congestion, pacing, anti-amplification, flow-control, stream-count,
  packet-size, queue, or buffer bounds;
- suppress required ACK, recovery, retransmission, credit, FIN, reset, close,
  cancellation, disposal, or shutdown progress;
- allow a later write to pass an earlier write on the same stream;
- change ownership or completion semantics after an operation is admitted;
- discard pending work, credit, recovery state, or retained buffers during a
  transition;
- use benchmark scenario IDs, requested concurrency, traffic-shape labels,
  peer identities, connection IDs, URLs, or application identities as
  production decision inputs;
- allocate an object, enumerate all streams, acquire a global lock, or emit
  high-cardinality metrics at a normal hot-path decision;
- self-update thresholds in production;
- explore a candidate on production traffic; or
- treat a throughput improvement as acceptance when correctness, latency,
  fairness, memory, loss, or host-health gates fail.

Forced test modes bypass selection only. They do not bypass these invariants.

## Portfolio Priority Model

Every axis is scored qualitatively against six questions:

1. **Expected value**: Can the axis materially affect throughput, latency,
   fairness, or memory across known regimes?
2. **Regime conflict**: Do existing results show that different choices win in
   different operating conditions?
3. **Seam readiness**: Is there already a stable, forceable decision seam?
4. **Observation readiness**: Can the relevant state be observed with bounded
   overhead and without feature leakage?
5. **Correctness isolation**: Can the choice remain subordinate to one
   correctness mechanism?
6. **Verification cost**: Can forced counterfactuals and rollback be proven
   without combining unrelated changes?

Priority means delivery order, not permission to implement.

| Priority | Meaning |
| --- | --- |
| `P0` | Existing or first-wave axis. Preserve, finish evidence, and use as the architectural template. |
| `P1` | Highest-value next axis after the current controller foundation is reviewed and stable. |
| `P2` | Valuable second-wave axis that needs a stronger seam, observations, or isolation proof. |
| `P3` | Longer-term or protocol-sensitive axis. Inventory and instrument first. |
| `P4` | Not currently an adaptive axis. Keep as a correctness mechanism, research topic, or explicit non-goal. |

## Portfolio Summary

| ID | Axis | Priority | Current readiness | Safe scope | Primary objective |
| --- | --- | --- | --- | --- | --- |
| `receive_credit_publication` | Receive-credit publication cadence | `P0` | Existing forced values and retained evidence | Productive read / pending-credit flush | Reduce credit chatter without blocking progress or harming duplex latency |
| `application_send_turn_planning` | First-write selection and continuation | `P0` | Stable injected planner seam | One connection-actor turn | Balance queue latency, throughput, and stream fairness |
| `oversized_write_admission_quantum` | Oversized-write chunks admitted per turn | `P0` | Accepted bounded selector, not controller-managed | One logical write | Avoid monopolization while retaining bulk efficiency |
| `application_send_batch_formation` | Writes packed into one packet plan | `P1` | Unit-forceable; no named campaign mode | One packet plan | Improve packet fill and reduce packet/operation overhead |
| `queued_send_burst_budget` | Consecutive queued-send datagrams per actor turn | `P1` | Existing static budget | One actor turn | Trade throughput against actor and cross-stream fairness |
| `actor_work_quantum` | Work processed per connection wake | `P1` | Observation-only; seam required | One shard dispatch / connection turn | Prevent hot connections from monopolizing a shard without excessive wakes |
| `packet_flush_cadence` | Coalescing versus prompt packet emission | `P1` | Correctness-critical safe points exist; policy seam absent | One packet construction opportunity | Trade sparse latency against saturated packet efficiency |
| `buffer_copy_coalescing` | Copy, segment, coalesce, and retain strategy | `P1` | Multiple mechanisms exist; unified seam absent | One admitted buffer/packet plan | Reduce allocations, copies, and retained memory without ownership risk |
| `ready_stream_fairness` | Service quantum across runnable streams | `P2` | Planner validation can support it | One actor turn | Bound starvation and tail latency under multiplexing |
| `application_datagram_batch_transport` | Segmented/contiguous versus ordinary sends | `P2` | Existing one-way adaptive precedent | Connection lifetime or endpoint capability epoch | Match batching to stream diversity and platform behavior |
| `adaptive_backpressure` | Earlier conservative admission below hard bounds | `P2` | Bounds exist; unified policy seam absent | New application admission | Stabilize memory and queue delay under saturation |
| `connection_shard_placement` | Connection-to-shard assignment | `P2` | No policy contract | Connection creation; migration is separate | Improve cross-connection balance and cache locality |
| `receive_delivery_quantum` | Receive delivery and application wake batching | `P2` | Research and seam discovery required | One receive-delivery turn | Trade wake overhead against read latency and fairness |
| `congestion_pacing_profile` | Congestion-controller or pacing profile selection | `P3` | Future connection-start seam only | Connection creation | Match transport control to path regime without mid-connection instability |
| `ack_behavior_profile` | ACK delay/frequency within peer and RFC constraints | `P3` | Protocol-sensitive; no adaptive seam | Connection or packet-number-space epoch | Reduce ACK overhead without degrading loss response |
| `crypto_execution_profile` | Inline, batched, or offloaded crypto execution | `P3` | Platform research required | Connection creation or bounded batch | Reduce CPU cost while bounding queueing latency |
| `http3_qpack_profile` | HTTP/3 priority and QPACK strategy | `P3` | Above-transport, separate component design | Request/header-block boundary | Balance compression, blocking risk, and request latency |
| `runtime_pressure_advice` | Host/process pressure snapshot | observation only | Schema planned; advisor absent | Coarse immutable sample | Supply optional context to conservative rules |

## Common Axis Contract

Every axis promoted beyond inventory must use the following contract.

### Stable identity

Each axis has:

- a lower-snake-case `axis_id`;
- a versioned closed enum of policy values;
- a separately named `legacy_current` value;
- a separately named `conservative` value, even when it initially matches
  `legacy_current`;
- stable bounded reason codes;
- a `policy_contract_version`; and
- a list of observation-contract versions with which it is compatible.

Axis IDs and policy names are provenance. Renaming requires a new version, not
an in-place rewrite of retained evidence.

### Operating modes

Each forceable axis must support:

- `legacy_current`: apply the exact retained selector;
- `baseline_only`: apply the axis's conservative value;
- `observe_only`: record observations without evaluating a selector;
- `shadow`: apply `legacy_current` and record the proposal;
- `forced_<value>`: apply one named value for a counterfactual campaign while
  retaining correctness guards; and
- `active_internal`: apply only a separately reviewed deterministic rule.

No axis-specific mode is a public API or public support promise during the
planning and internal evidence periods.

### Decision scope and latch

Every axis must name one safe scope:

| Scope | Examples | Required rule |
| --- | --- | --- |
| Connection creation | shard placement, congestion-control family, platform crypto mode | Immutable for the connection unless a separate migration design exists |
| Connection epoch | coarse policy snapshot, one-way pressure promotion | Changes only at an actor-safe boundary with hysteresis |
| Actor turn | planner selection, burst budget, actor quantum | Applies only to work selected in that turn |
| Packet plan | batch formation, packet fill, flush choice | Immutable from construction through commit or clean abandonment |
| Logical operation | oversized-write fragmentation and completion | Immutable for the operation's entire ownership and completion lifetime |
| Productive read | receive-credit cadence | May use the latest safe value, but pending credit and progress guards remain authoritative |
| Admission | buffer strategy, backpressure behavior | Ownership and limits latch when work is accepted |

An axis without a precise scope and latch is not implementation-ready.

### Correctness guard

The seam-local consumer must validate:

- lifecycle and terminal state;
- cancellation and disposal;
- flow-control and stream-count headroom;
- congestion, pacing, and anti-amplification authority;
- packet-size and payload budget;
- queue and retained-memory bounds;
- ordering and fairness invariants;
- recovery-required work;
- rule and snapshot compatibility; and
- missing, stale, saturated, contradictory, or out-of-domain observations.

Failure selects conservative progress at the next safe boundary. It must not
throw away already admitted work.

### Observation declaration

Each axis declares:

- required signals;
- optional signals;
- maximum signal age;
- arithmetic representation;
- saturation behavior;
- threshold-crossing triggers;
- evaluation cadence;
- out-of-domain conditions; and
- signals retained only for analysis and prohibited from production rules.

The observation cost must be measured independently. New per-stream scans or
per-packet allocations are prohibited.

### Outcomes

Every axis campaign measures at least:

- exact payload and protocol correctness;
- failed, timed-out, canceled, and disposed operations;
- application throughput;
- p50, p95, and p99 completion latency;
- stream fairness or an explicit `unassessed` value;
- queue delay and service time;
- allocations, pool rent, outstanding pool bytes, and peak retained bytes;
- loss, retransmission, PTO, and ACK pressure where relevant;
- policy evaluations, transitions, dwell, and reason counts;
- target, generator, CPU, memory, and runtime pressure; and
- requested versus effective workload shape.

Missing outcomes stay null or unassessed. Request latency may not be relabeled
as stream fairness, and pool rent may not be relabeled as managed allocation.

### Counterfactual evidence

Every policy value must be forced independently against the same frozen binary
cohort. Default order is A/B/B/A or B/A/A/B. A controller-selected policy alone
does not establish that a different policy would have been worse.

### Rollback

Each axis must provide an internal force-legacy or force-conservative override
before any active application is reviewed. Rollback:

- affects only new work at the axis's safe boundary;
- preserves in-flight ownership and completion;
- retains controller and mechanism state required for correctness;
- records the trigger and first affected epoch;
- creates a new append-only result; and
- never deletes the failed candidate or negative evidence.

## Detailed Axis Specifications

## 1. Receive-Credit Publication

**Axis ID:** `receive_credit_publication`  
**Priority:** `P0`  
**Current disposition:** Retained behavior and first controller template  
**Primary owner:** `QuicConnectionRuntime`, `QuicStream.ReadAsync`, and
`QuicConnectionStreamState`

### Optimization question

When should consumed receive bytes be converted into MAX_DATA and
MAX_STREAM_DATA updates? Immediate publication protects low-latency progress
and duplex behavior. Bounded batching can reduce control-frame generation,
actor handoffs, and packet overhead during many-stream receive-heavy traffic.

### Named policy values

- `legacy_current`: exact retained sticky selector.
- `immediate`: publish eligible credit promptly.
- `read_dominant_batch`: retained bounded half-window mechanism, eligible only
  under its reviewed guards.
- Future cadences require a new plan and new enum values. The rejected
  universal, quarter-window, non-sticky, and duplex-reactivating variants must
  not be revived under new names.

### Required observations

- `has_issued_application_data`;
- `live_observer_streams`;
- connection and minimum-stream receive headroom;
- pending connection and maximum stream credit;
- time since last credit publication;
- inbound rate and receive-active stream count;
- peer blocked evidence;
- lifecycle, terminal, cancellation, and disposal flags; and
- missing, stale, saturation, recovery, and flow-progress guards.

### Safe application boundary

The value may be read for a productive application read or pending-credit
flush. Pending credit survives a transition. Low-headroom, peer-blocked,
terminal, saturation, and recovery conditions force immediate progress.

### Latching

The connection-lifetime `has_issued_application_data` fact is monotonic. Once
true, a read-dominant candidate is ineligible for that connection. A controller
cannot infer that duplex traffic ended and clear the fact.

### Primary risks

- blocked peers and receive-window exhaustion;
- control-frame chatter;
- duplex tail-latency regressions;
- reactivation after transient read dominance;
- numeric saturation;
- terminal credit loss; and
- accidental coupling to stream-count benchmark labels.

### Required campaigns

- c1/c4 upload, download, duplex, and request/response;
- c16/c24 receive-heavy target cells;
- retained-negative duplex screens;
- small receive windows and slow consumers;
- peer-blocked recovery;
- FIN, reset, cancellation, disposal, shutdown, loss, and PTO;
- c32 neighbor; and
- c64+ stress only with healthy target and generator evidence.

### Acceptance emphasis

Zero progress or correctness failures. Exact reproduction of the frozen
selector is required before semantic widening. Tail latency, memory, and
control-frame ratio are co-equal with throughput.

## 2. Application-Send Turn Planning

**Axis ID:** `application_send_turn_planning`  
**Priority:** `P0`  
**Current disposition:** Stable seam; future policies require fresh evidence  
**Primary owner:** `IQuicApplicationSendTurnPlanner`, runtime listener factory,
application-send queue, and connection actor

### Optimization question

Which legal queued write should begin a connection-actor turn, and should
another application-send turn be scheduled after the current plan completes?
Sparse traffic benefits from prompt service. Saturated multiplexing may benefit
from locality and bounded continuation. An aggressive fixed quantum can harm
tail latency or fairness.

### Named policy values

The exact final names require review, but campaigns should preserve:

- `legacy_current`: current priority and stable-sequence behavior;
- `fair_prompt`: prioritize oldest legal work while preserving priority;
- `locality_bounded`: prefer bounded compatible work that improves packet or
  buffer locality;
- `pressure_bounded`: allow additional continuation only under sustained,
  in-domain queue pressure; and
- any rejected fixed-quantum planner as a retained negative, never silently
  repackaged.

### Required observations

- queued writes and logical backlog bytes;
- distinct queued streams;
- oldest queue age and queue-delay EWMA;
- actor service-time EWMA;
- queue-to-service ratio;
- burst-limit hits;
- active/runnable send streams;
- write-completion EWMA;
- bytes in flight and congestion window;
- retained send buffers and bytes; and
- lifecycle, recovery, resource, and out-of-domain guards.

### Safe application boundary

One connection-actor turn. The planner selects only from a bounded immutable
view of legal queued work. The runtime validates the plan against priority,
stream sequence, ownership, congestion, pacing, payload, and terminal rules.

### Latching

A plan lasts for one turn. A selected logical write retains its independent
operation-level latches. A later policy snapshot cannot reorder already
committed work.

### Primary risks

- same-stream reordering;
- starvation across priorities or streams;
- queue-tail amplification;
- actor monopolization;
- plan-validation overhead;
- planner allocation;
- unstable promotion and demotion; and
- confusing target throughput with cross-connection fairness.

### Required campaigns

- sparse single-stream request/response;
- sustained single-stream bulk;
- one connection with 4, 16, 24, 32, 64, and 100 runnable streams;
- multiple connections with mixed active-stream counts;
- priority mixtures;
- deterministic stream churn;
- asymmetric payload sizes;
- cancellation and disposal of queued and selected writes;
- loss/recovery and constrained congestion windows; and
- matched pool-retention and queue-delay measurements.

### Acceptance emphasis

Same-stream order and exact completion are absolute. Stream fairness needs a
real bounded metric. A throughput gain that increases oldest queue age,
low-cardinality p95, or retained memory beyond its guardrail is negative.

## 3. Oversized-Write Admission Quantum

**Axis ID:** `oversized_write_admission_quantum`  
**Priority:** `P0`  
**Current disposition:** Accepted bounded selector; inventory before migration  
**Primary owner:** `QuicConnectionRuntime.Streams`

### Optimization question

How many bounded fragments of a large logical write may be admitted and
processed in one actor turn? More fragments reduce continuation overhead and
can improve bulk throughput. Fewer fragments protect other runnable streams
and connections from monopolization.

### Named policy values

- `legacy_current`;
- `single_fragment`;
- `bounded_multi_fragment`, representing the retained accepted quantum; and
- future values only when the quantum is expressed independently of benchmark
  cardinality labels.

### Required observations

- logical write remaining bytes;
- maximum current packet/application payload budget;
- distinct queued and runnable send streams;
- queue delay and service time;
- actor turn and continuation counts;
- bytes in flight and congestion headroom;
- retained buffer bytes;
- write completion latency; and
- cancellation, disposal, terminal, and resource guards.

### Safe application boundary and latch

Selection occurs at logical-write admission and is carried through
fragmentation, continuation, ownership, cancellation, and completion. It
cannot change halfway through the same logical write.

### Primary risks

- in-flight ownership changes;
- duplicate or omitted fragments;
- completion firing more than once;
- cancellation races;
- large-write head-of-line blocking;
- retained-buffer growth; and
- a threshold tuned to observer count rather than transferable pressure.

### Acceptance emphasis

Fragment identity, byte-exact completion, single completion, cancellation,
disposal, and buffer return must be proven. Compare continuation overhead,
fairness, p95/p99, and retained memory—not throughput alone.

## 4. Application-Send Batch Formation

**Axis ID:** `application_send_batch_formation`  
**Priority:** `P1`  
**Current disposition:** Highest-priority new send-path axis after review  
**Primary owner:** `QuicApplicationSendScheduler`,
`QuicApplicationSendQueue`, packet construction, and application-send runtime

### Optimization question

How many compatible queued writes should be represented in one outbound packet
plan, within the payload budget? Small batches minimize planning cost and
latency. Larger legal batches can improve packet fill, reduce packets per
logical operation, and amortize encryption and socket-send overhead.

### Candidate policy values

- `single_eligible`;
- `legacy_current`;
- `fill_bounded`;
- `stream_diverse_bounded`; and
- `latency_guarded_fill`.

The names are provisional until the existing scheduler behavior is mapped
exactly.

### Required observations

- packet payload budget and expected fill;
- queued write count and logical backlog;
- distinct queued streams;
- oldest queue age;
- queue-to-service ratio;
- average eligible write size;
- packet fill EWMA;
- packets per logical operation;
- control-frame ratio;
- bytes in flight and congestion headroom;
- retained send buffers; and
- sparse/interactive guard evidence.

### Safe application boundary

One packet plan. The runtime computes the legal eligible set and maximum
payload budget first. Policy may choose a smaller legal subset. Packet
protection, packet number, stream offsets, FIN, retransmission ownership, and
congestion accounting commit atomically through the existing mechanism.

### Hard limits

The policy cannot:

- exceed the runtime payload budget;
- join writes whose ordering or frame semantics conflict;
- merge ownership or completion records;
- delay recovery-required frames;
- hold an incomplete packet plan across an unsafe boundary; or
- force raw stream data onto a batch path that lacks equivalent correctness
  proof.

### Primary risks

- planning complexity proportional to queue length;
- retained plan objects or copied payloads;
- delayed oldest work;
- mixed-stream completion bugs;
- packet-fill improvement offset by queue latency;
- larger retransmission units; and
- platform-specific segmented-send behavior.

### Required campaigns

Cross small and mixed payloads, sparse/bursty/sustained arrival, 1-100 streams,
1-many connections, clean and controlled loss, normal and constrained
congestion windows, and platform/architecture cohorts. Retain packet fill,
packet count, crypto time, socket calls, queue delay, request latency, and
buffer retention.

### Acceptance emphasis

A candidate should demonstrate lower packets per useful byte or lower CPU cost
without worse correctness, low-count p95, fairness, loss amplification, or
retained memory.

## 5. Queued-Send Burst Budget

**Axis ID:** `queued_send_burst_budget`  
**Priority:** `P1`  
**Current disposition:** Existing static policy; suitable for isolated forcing  
**Primary owner:** `QuicSendPolicy` and queued-send service

### Optimization question

How many authorized application datagrams may one connection emit from queued
work before yielding? Higher budgets improve saturated throughput and reduce
wake overhead. Lower budgets improve cross-stream and cross-connection
fairness, responsiveness, and actor predictability.

### Candidate policy values

- `legacy_current`;
- `latency_bounded`;
- `balanced`;
- `throughput_bounded`; and
- `resource_conservative`.

Each value is a cap below the already computed legal maximum. No candidate may
raise congestion, pacing, anti-amplification, handshake, packet, or endpoint
budgets.

### Required observations

- runnable streams and queued writes;
- backlog bytes;
- queue age and service time;
- burst-limit hits;
- useful work per turn;
- follow-on wake count;
- bytes in flight and congestion window;
- socket backlog advice when available;
- neighboring connection/shard pressure; and
- memory/resource guard state.

### Safe application boundary and latch

One actor turn. Recompute on the next turn. An in-progress packet plan remains
latched.

### Primary risks

- hot connection monopolization;
- excess wakeups at low caps;
- packet underfill;
- fairness metrics missing at the connection/shard boundary;
- confounding with the planner and batch-formation axes; and
- accidental increase above hard budgets.

### Interaction rule

This axis must first be measured with the planner and batch-formation values
fixed. Only after independent effects are understood may a planned factorial
campaign study interactions.

## 6. Actor Work Quantum

**Axis ID:** `actor_work_quantum`  
**Priority:** `P1`  
**Current disposition:** Observe first; seam and ownership design required  
**Primary owner:** `QuicConnectionRuntimeShard`, connection runtime, deadline
scheduler, and follow-on flush paths

### Optimization question

How much work for one connection should a shard process before allowing other
ready connections and timers to run? Large quanta amortize dispatch and improve
cache locality. Small quanta protect cross-connection fairness and timer
latency.

### Potential policy values

- `legacy_current`;
- `latency_guarded`;
- `balanced_work_units`;
- `throughput_guarded`; and
- `pressure_conservative`.

These values cannot be defined only as event counts. One receive packet, one
large application write, and one flow-credit flush have different costs.

### Required observation foundation

- actor service-time EWMA;
- actor turns and useful work units;
- work item counts by bounded kind;
- follow-on flush counts by bounded kind;
- queue delay;
- runnable connection count per shard;
- oldest shard item age;
- deadline/timer lateness;
- per-connection backlog and runnable streams;
- CPU pressure advice; and
- starvation and progress counters.

### Safe application boundary

One shard dispatch of one connection runtime. The connection must leave itself
in a repostable, progress-safe state when the quantum expires. Required
recovery, terminal, cancellation, disposal, and timer work can bypass a normal
quantum.

### Required seam work

Before a policy exists, architecture must define:

- the unit of bounded work;
- which operations are preemptible;
- how follow-on work is reposted exactly once;
- how timers retain priority;
- how inline completions behave;
- how a connection reports remaining work without enumerating queues;
- how shutdown drains; and
- how shard-level observations are supplied without a global lock.

### Primary risks

- lost wakeups;
- duplicate reposts;
- timer starvation;
- incomplete terminal drain;
- increased context switching;
- cross-connection unfairness;
- global synchronization; and
- coupling one connection's policy to private state of another.

### Acceptance emphasis

This axis needs dedicated liveness, repost, timer, recovery, terminal, and
multi-connection fairness proofs before performance comparison.

## 7. Packet Flush Cadence

**Axis ID:** `packet_flush_cadence`  
**Priority:** `P1`  
**Current disposition:** Safe-point discovery and observation first  
**Primary owner:** packet construction, routing/send paths, `QuicSendPolicy`,
recovery, congestion, pacing, and endpoint host

### Optimization question

Should newly authorized application data be emitted promptly or briefly
coalesced until a fuller packet can be formed? Prompt flush protects sparse
latency. Bounded coalescing can improve packet fill and reduce crypto and
socket-send overhead during bursts.

### Candidate policy values

- `prompt`;
- `legacy_current`;
- `bounded_coalesce`;
- `pressure_fill`; and
- `latency_guarded_fill`.

No policy may delay an ACK, probe, retransmission, required credit, path
validation, terminal frame, or other progress-critical work past its
authoritative deadline.

### Required observations

- packet fill ratio;
- eligible backlog bytes;
- oldest queued age;
- arrival-gap EWMA;
- queue-to-service ratio;
- packets per logical operation;
- crypto and socket-send cost;
- pacing next-send time;
- ACK/recovery/credit pending flags;
- loss and retransmission pressure; and
- quiescent versus active regime.

### Safe application boundary

At an existing authorized packet-construction opportunity before externally
visible packet number and accounting commit. A bounded delay must be owned by
the existing deadline scheduler with one cancelable generation, not an
untracked sleep or application timer.

### Primary risks

- delayed progress frames;
- timer generation races;
- increased sparse p95/p99;
- packet-number/accounting rollback;
- amplification or pacing violations;
- coalescing latency hidden by aggregate throughput; and
- interaction with send batch and burst axes.

### Acceptance emphasis

Prompt mode is the conservative fallback. Require timer determinism,
same-binary sparse-latency controls, and explicit proof that required protocol
work bypasses coalescing.

## 8. Buffer Copy And Coalescing Strategy

**Axis ID:** `buffer_copy_coalescing`  
**Priority:** `P1`  
**Current disposition:** Mechanism inventory and ownership contract required  
**Primary owner:** application-send queue, stream send/receive state, packet
builder, buffer pool, endpoint/socket send, and completion owners

### Optimization question

When should data be copied into a contiguous pooled buffer, retained as
segments, coalesced into a batch, or passed through an existing owned memory
region? The fastest choice varies with payload size, segment count, lifetime,
platform scatter/gather support, memory pressure, and completion timing.

### Candidate policy values

- `legacy_current`;
- `copy_small`;
- `segment_preserving`;
- `coalesce_bounded`;
- `memory_conservative`; and
- platform-specific values only when capability and fallback are explicit.

### Required observations

- payload and remaining logical bytes;
- segment count and sizes;
- retained send/receive buffer count and bytes;
- pool rent, return, outstanding, and peak bytes;
- managed allocation where measurable;
- copy bytes and copy operations;
- completion age;
- socket-send capability and backlog;
- memory-pressure advice; and
- cancellation, disposal, terminal, and ownership state.

### Safe application boundary and latch

The strategy is selected when a buffer or packet plan is admitted. The owner,
return path, completion trigger, and cancellation behavior latch for the
entire lifetime of that memory. A controller transition cannot convert an
already retained segment into another ownership form.

### Hard rules

- exactly one owner at every point;
- exactly one terminal release;
- no use after return;
- no return while kernel or crypto work still references memory;
- no hidden unbounded coalescing;
- hard retained-byte limits remain authoritative; and
- sensitive plaintext lifetime may not be extended for performance.

### Required campaigns

Payload sizes from tiny headers through multi-megabyte writes; one and many
segments; cancellation before and after admission; disposal and shutdown;
loss/retransmission; constrained memory; Windows, Linux x64, and Linux/macOS
ARM64 capability cohorts; and allocation/pool/copy/retention attribution.

### Acceptance emphasis

Ownership tests and memory bounds precede throughput tests. A CPU or throughput
gain with higher unexplained peak retained bytes is negative.

## 9. Ready-Stream Fairness

**Axis ID:** `ready_stream_fairness`  
**Priority:** `P2`  
**Current disposition:** Build on the planner seam after a real fairness metric  
**Primary owner:** application-send planner and queue

### Optimization question

How much service should one runnable stream receive relative to others of the
same and different priorities? Strict sequence and priority preserve semantics
but do not alone define a useful service quantum under sustained multiplexing.

### Candidate policy values

- `legacy_current`;
- `oldest_eligible`;
- `round_robin_within_priority`;
- `deficit_bounded`; and
- `latency_guarded_heavy_stream`.

### Required observations and outcomes

- runnable streams by priority;
- bytes and operations served per stream;
- oldest unserved age;
- maximum and percentile service gap;
- Jain-style fairness or another reviewed bounded fairness statistic;
- completion latency by workload-neutral stream cohort;
- heavy/light stream mixture;
- cancellations and closed streams; and
- aggregate throughput and retained memory.

Production selection must not require stream identity. Bounded actor-local
state may maintain legal rotation or deficits, but dataset export uses
pseudonymous analysis keys.

### Safe application boundary

One actor turn or selected write. Same-stream sequence and priority invariants
remain authoritative.

### Primary risks

- throughput loss from excessive rotation;
- state growth proportional to streams;
- stale fairness state after close/reset;
- priority inversion;
- treating equal bytes as equal service for unequal operations; and
- using request latency as a false fairness proxy.

### Readiness gate

Do not implement this axis until the fairness outcome definition and bounded
state cost are reviewed.

## 10. Application Datagram Batch Transport

**Axis ID:** `application_datagram_batch_transport`  
**Priority:** `P2`  
**Current disposition:** Existing adaptive precedent; keep independent  
**Primary owner:** `IQuicApplicationDatagramBatchPolicy`, endpoint host, and
platform send implementation

### Optimization question

When should the runtime use contiguous/segmented batch sends versus ordinary
datagrams? Benefits depend on platform APIs, packet size, contiguous work,
stream diversity, socket behavior, and pressure.

### Existing rule

The current policy begins on a batching-capable path and may one-way promote to
ordinary datagrams after repeated distinct-stream pressure. Its state machine
must not be merged into the connection controller without a compatibility
decision.

### Future policy requirements

- explicit capability probe;
- stable platform and fallback identity;
- forced batch and ordinary modes;
- socket error and partial-send semantics;
- connection-lifetime or one-way latch;
- send-call, datagram, segment, and byte outcomes;
- CPU and allocation measurements; and
- exact parity for congestion and recovery accounting.

### Primary risks

- platform-specific semantics;
- partial batch failure;
- buffer lifetime extension;
- different completion timing;
- hidden interaction with packet fill; and
- mistakenly treating one platform's result as universal.

## 11. Adaptive Backpressure

**Axis ID:** `adaptive_backpressure`  
**Priority:** `P2`  
**Current disposition:** Conservative admission below hard limits only  
**Primary owner:** application admission, send queue, receive retention, buffer
pool, and endpoint backlog

### Optimization question

Should new work be delayed, bounded, or rejected earlier than the hard resource
limit when queue delay, retained memory, or host pressure indicates impending
saturation? Earlier backpressure can stabilize memory and tail latency.
Overly conservative backpressure can reduce throughput or deadlock progress.

### Candidate policy values

- `legacy_current`;
- `early_delay`;
- `memory_conservative`;
- `queue_conservative`; and
- `host_pressure_conservative`.

Policies may become more conservative before a hard bound. They may never
raise, ignore, or dynamically expand a hard bound.

### Required observations

- logical backlog and queued operation count;
- retained send/receive bytes;
- pool outstanding and peak;
- queue delay and completion age;
- socket backlog advice;
- CPU, thread-pool, and managed-memory pressure advice;
- application cancellation rate;
- peer flow-control and congestion state; and
- progress and terminal guards.

### Safe application boundary

New operation admission. Already admitted ownership and completion semantics
remain unchanged.

### Primary risks

- self-inflicted deadlock;
- starvation under stale pressure;
- cross-layer feedback oscillation;
- conflating congestion with memory pressure;
- application-visible behavior changes;
- public API implications; and
- missing advisor data treated as zero pressure.

### Readiness gate

Define whether the public behavior is wait, bounded queue, synchronous failure,
or asynchronous failure before implementation. That is a product/API decision,
not merely a performance choice.

## 12. Connection Shard Placement

**Axis ID:** `connection_shard_placement`  
**Priority:** `P2`  
**Current disposition:** Connection-start policy research  
**Primary owner:** listener/client host and runtime shard router

### Optimization question

Which shard should own a new connection? Round-robin placement is simple and
deterministic. Load-aware placement may improve balance. Locality-aware
placement may improve cache behavior. A bad global policy can add contention
or move the bottleneck.

### Candidate policy values

- `legacy_current`;
- `round_robin`;
- `least_connections`;
- `least_recent_service_pressure`; and
- `bounded_power_of_two_choices`.

### Required observations

- active connection count per shard;
- runnable connection count;
- shard queue age and depth;
- service-time EWMA;
- timer lateness;
- CPU affinity/topology when reliably available; and
- placement decision cost.

### Safe application boundary and latch

Connection creation. The selected shard owns the connection for its lifetime.
Mid-connection migration is a separate architecture problem involving timers,
inbox ownership, packet routing, and outstanding operations and is not implied
by this axis.

### Primary risks

- global locks or hot counters;
- nondeterministic placement;
- stale load snapshots;
- herding;
- topology-specific overfitting;
- cross-shard timer/route bugs; and
- impossible counterfactual comparison after placement changes connection
  history.

### Acceptance emphasis

Placement must remain O(1) or bounded-choice, deterministic given its snapshot,
and correct when load data is absent. Evaluate multi-connection throughput,
queue age, shard balance, timer latency, and CPU—not single-connection speed.

## 13. Receive Delivery Quantum

**Axis ID:** `receive_delivery_quantum`  
**Priority:** `P2`  
**Current disposition:** Seam discovery and instrumentation first  
**Primary owner:** packet receive processing, stream receive state, observer
delivery, and application `ReadAsync`

### Optimization question

How much already-validated receive data should be made available or signaled
per delivery turn? Larger delivery quanta can reduce wakes and lock/actor
handoffs. Smaller quanta can improve interactive latency and fairness across
streams.

### Potential policy values

- `legacy_current`;
- `prompt_delivery`;
- `bounded_batch_delivery`; and
- `pressure_batch_delivery`.

These are hypotheses, not approved implementations.

### Required observations

- receive-active and runnable streams;
- retained receive bytes and buffers;
- application consumption rate;
- inbound byte rate;
- read completion latency;
- observer/wake counts;
- flow-control headroom and blocked time;
- stream service gaps; and
- terminal FIN/reset/cancellation state.

### Safe boundary

One delivery notification or productive read boundary. Validated data,
offsets, FIN, reset, and flow-control accounting remain authoritative.

### Primary risks

- delayed EOF or reset;
- receive-buffer retention;
- observer lifetime bugs;
- starvation;
- duplicate notification;
- interaction with receive-credit publication; and
- changing application-visible read chunking.

### Interaction rule

Measure with receive-credit publication fixed first. Delivery and credit
cadence affect each other's observations and cannot be interpreted from an
uncontrolled combined campaign.

## 14. Congestion And Pacing Profile

**Axis ID:** `congestion_pacing_profile`  
**Priority:** `P3`  
**Current disposition:** Future connection-start strategy; no mid-connection switching  
**Primary owner:** recovery controller, congestion controller, pacing, and
connection options

### Optimization question

Could a connection choose among separately correct congestion-control or
pacing profiles based on platform, path, or explicitly configured deployment
context? Different paths can favor different controllers, but adaptation here
has far greater correctness, fairness, and network externality risk than local
queue policies.

### Boundary

Initial selection may occur only at connection creation. Mid-connection
switching is prohibited until a separate design defines state translation,
bytes-in-flight ownership, recovery history, pacing credit, rollback, and peer
impact.

### Permitted observations

Initial choice may use explicit internal configuration and stable platform
capability. Runtime RTT, loss, ECN, delivery rate, and PTO observations may be
retained for offline research, but no production rule is authorized here.

### Primary risks

- network unfairness;
- unstable control loops;
- path-specific overfitting;
- invalid state translation;
- loss amplification;
- interaction with ACK behavior;
- misleading same-host benchmarks; and
- operational support complexity.

### Acceptance burden

Requires network emulation, peer diversity, controlled loss/delay/bandwidth,
long-lived transfers, fairness against reference flows, ECN, migration/path
change, recovery, and multi-host holdouts. This is not an early adaptive axis.

## 15. ACK Behavior Profile

**Axis ID:** `ack_behavior_profile`  
**Priority:** `P3`  
**Current disposition:** Protocol-sensitive research only  
**Primary owner:** ACK generation, peer transport parameters, recovery, and
timer state

### Optimization question

Can ACK frequency or delay be selected within negotiated and RFC-compliant
bounds to reduce ACK overhead without degrading recovery or peer throughput?

### Hard authority

ACK generation requirements, peer parameters, packet-number spaces, ACK range
correctness, immediate-ACK conditions, ECN feedback, and recovery deadlines
are mechanisms. Policy may only choose a stricter legal value within their
bounds.

### Required observations

- packet arrival rate and reordering;
- ACK-eliciting packets since last ACK;
- negotiated maximum ACK delay;
- RTT and variance;
- loss, retransmission, PTO, and reordering evidence;
- ACK frame and control-frame ratio;
- peer blocked/progress evidence; and
- timer lateness.

### Primary risks

- delayed loss recovery;
- interoperability failures;
- ACK timer races;
- invalid ACK-frequency assumptions;
- path asymmetry;
- peer performance regression; and
- optimizing local CPU at network cost.

### Readiness gate

Do not create adaptive behavior until the relevant RFC/extension authority,
peer capability contract, deterministic timer tests, and controlled-network
campaigns are explicit.

## 16. Crypto Execution Profile

**Axis ID:** `crypto_execution_profile`  
**Priority:** `P3`  
**Current disposition:** Platform capability and cost research  
**Primary owner:** packet protection, crypto provider, packet builder, and
endpoint execution model

### Optimization question

Should packet protection execute inline, in a bounded batch, or through a
platform-specific accelerated path? Batching and offload may reduce CPU per
packet at high rates but add queue latency and ownership complexity.

### Boundary and latch

Provider/capability selection should latch at connection creation. A bounded
batch size may be an actor-turn or packet-batch decision only after ownership,
ordering, packet-number, failure, and completion semantics are proven.

### Required observations

- packet size and rate;
- crypto service-time EWMA;
- crypto queue delay;
- batch fill;
- CPU capability;
- packet latency;
- retained plaintext/ciphertext buffers;
- errors and fallback counts; and
- memory and thread-pool pressure.

### Hard rules

- packet numbers and nonces remain unique;
- authenticated data and key phase remain exact;
- plaintext ownership and lifetime are bounded;
- failures cannot partially commit accounting;
- key update and retained-key behavior are identical; and
- fallback is deterministic and correct.

### Primary risks

- security regression;
- key/nonce misuse;
- plaintext retention;
- cross-thread ordering;
- platform-specific failure behavior; and
- latency hidden by throughput.

### Acceptance burden

Requires cryptographic known-answer tests, fuzz/property coverage, key update,
loss/retransmission, cancellation/shutdown, platform capability absence, and
security review before performance evidence matters.

## 17. HTTP/3 Priority And QPACK Profile

**Axis ID:** `http3_qpack_profile`  
**Priority:** `P3`  
**Current disposition:** Separate above-transport architecture slice  
**Primary owner:** `Incursa.Quic.Http3`, QPACK encoder/decoder, request
scheduler, and HTTP/3 control streams

### Optimization question

Could HTTP/3 select request priority service, header encoding strategy, dynamic
table usage, blocked-stream allowance, or header batching based on observable
request/header pressure? Compression efficiency, blocking risk, memory, and
request latency can conflict.

### Separation rule

This is not a transport scheduler axis. It may reuse the observation,
controller, forced-mode, provenance, and offline-learning patterns, but it
needs HTTP/3/QPACK-specific requirements, observations, outcomes, and rollback.
Transport and HTTP/3 axes must not first activate in the same candidate.

### Potential policy areas

- static-only versus bounded dynamic-table encoding;
- insertion thresholds;
- blocked-stream budget below the peer limit;
- eviction strategy within hard capacity;
- request priority service quantum; and
- header-block batching.

### Required observations

- header block size and repetition;
- dynamic table occupancy and churn;
- encoder/decoder blocked duration;
- blocked stream count and limit;
- compression ratio;
- request priority and queue age;
- header decode latency;
- retained QPACK memory; and
- control-stream and cancellation state.

Production rules cannot consume route names, header names/values, URLs, or
application identity.

### Primary risks

- QPACK deadlock or excessive blocking;
- control-stream correctness;
- memory retention;
- priority starvation;
- privacy leakage through observations;
- overfitting to benchmark headers; and
- interaction with transport stream scheduling.

## 18. Runtime Pressure Advice

**Surface ID:** `runtime_pressure_advice`  
**Priority:** observation foundation, not an adaptive axis  
**Current disposition:** Optional immutable snapshot design

### Purpose

Some policy decisions may need coarse context that a single connection cannot
observe, such as CPU saturation, thread-pool delay, managed-memory pressure, or
socket backlog. The advisor may publish one immutable coarse snapshot that
connections sample at epoch boundaries.

### Required properties

- optional and disableable;
- bounded sampling cadence;
- immutable snapshot;
- no connection callbacks;
- no global decision lock;
- stable version and monotonic capture time;
- explicit missing and stale masks;
- low-cardinality fields;
- platform capability declaration; and
- conservative rules when required advice is missing.

### Prohibited behavior

The advisor must not:

- select policies;
- mutate connection state;
- expose benchmark labels or identities;
- require every connection to register;
- publish per-connection metric tags;
- make connection progress depend on its availability; or
- infer that host pressure excuses correctness or resource-bound violations.

## Surfaces That Are Not Adaptive Axes

The following are correctness mechanisms or unsupported widening targets:

| Surface | Why it is not an axis |
| --- | --- |
| Packet-number allocation | Uniqueness and ordering are protocol invariants. |
| Packet protection and key-phase mechanics | Security-critical authority; only execution provider may someday be selectable. |
| MAX_STREAMS release and replay | Required liveness and reliability mechanism. Coalescing may be optimized only if exact release semantics remain unchanged. |
| MAX_DATA/MAX_STREAM_DATA pending-value coalescing | Preserves highest required credit and progress; not a discretionary cadence after publication is required. |
| Loss declaration and retransmission eligibility | Recovery correctness. Congestion profile selection does not make loss evidence optional. |
| Anti-amplification | Mandatory safety bound. |
| Flow-control and stream-count limits | Hard peer/local bounds. Policy may act more conservatively, never exceed them. |
| FIN, reset, cancellation, disposal, and shutdown | Terminal progress and ownership authority. |
| Same-stream ordering | Semantic invariant. |
| Buffer ownership and terminal return | Memory-safety invariant. Only the strategy selected before ownership latches may vary. |
| Path validation and path selection | Separate protocol architecture. No adaptive widening is implied by this roadmap. |
| Rule self-modification | Prohibited. Offline-derived rules are immutable and reviewed. |

## Axis Interaction Policy

Many axes interact. That is not permission to activate them together.

### Known interaction groups

| Group | Axes | Confounding risk |
| --- | --- | --- |
| Send selection | turn planning, ready-stream fairness, burst budget | All affect who waits and for how long |
| Packet efficiency | batch formation, packet flush cadence, datagram batch transport, crypto batching | All affect packet fill, send calls, and per-packet cost |
| Memory | oversized-write quantum, buffer strategy, batch formation, backpressure | All affect retained bytes and completion timing |
| Receive path | receive delivery quantum, receive-credit publication | Delivery changes consumption timing and credit observations |
| Actor service | actor work quantum, burst budget, planner continuation | All affect wake cost and cross-connection fairness |
| Network control | congestion/pacing, ACK behavior | Coupled feedback loops and peer impact |
| HTTP/3 | QPACK/profile, transport stream fairness | Application scheduling and transport service can amplify each other |

### Required sequence

1. Hold all other axes at `legacy_current`.
2. Force each value of one axis.
3. Establish correctness and basic effect.
4. Run shadow for that one axis.
5. If the axis clears review, freeze its accepted baseline.
6. Only then design a bounded factorial campaign for one named interaction
   pair.
7. Never infer interaction from independently collected unmatched campaigns.

An interaction rule requires its own version, dataset cohort, held-out
validation, and rollback analysis.

## Observation And Dataset Additions By Axis

Before adding counters, Codex must map every requested signal to the existing
observation schema and classify it:

- `existing`;
- `derivable`;
- `new_counter`;
- `advisor_optional`; or
- `analysis_only`.

For every new signal record:

- owner;
- exact update site;
- type and unit;
- saturation rule;
- reset/epoch rule;
- expected hot-path cost;
- availability and stale behavior;
- whether it can be a production feature;
- schema version impact; and
- focused neutrality test.

One offline row remains one bounded connection epoch. Axis-specific outcomes
are added to a versioned result/epoch contract, not hidden in unstructured
logs. Excluded and correctness-failed rows remain present with explicit
reasons.

## Offline Learning Workflow For Multiple Axes

### Phase 1: data quality

- Validate checksums, joins, forced/applied policy identity, requested/effective
  workload shape, and host/generator health.
- Preserve all rows.
- Exclude invalid rows from training without deleting them.
- Group epochs by connection and run; never treat epochs from one connection
  as independent train/test samples.

### Phase 2: single-axis effects

- Estimate constrained policy effect within matched forced-policy cohorts.
- Identify regime boundaries using observable features only.
- Check correctness, latency, fairness, memory, and recovery constraints before
  ranking throughput.
- Hold out complete hosts and workload families.

### Phase 3: regime discovery

Permitted exploratory tools include:

- decision and regression trees;
- generalized additive models;
- interaction analysis;
- clustering;
- change-point analysis;
- partial-dependence review; and
- feature stability across hosts and architectures.

Workload labels may explain a result during analysis but cannot enter a
production rule.

### Phase 4: rule derivation

- Rewrite a candidate boundary as deterministic integer/fixed-point logic.
- Define entry, leave, dwell, and fallback behavior.
- Remove leaked or unstable features.
- Adversarially test threshold edges, missing values, stale values, arithmetic
  saturation, and contradictory signals.
- Replay against held-out rows.
- Assign a new immutable rule version.

### Phase 5: shadow

- Apply `legacy_current`.
- Record the proposal and reason.
- Require deterministic replay.
- Join recommendations to compatible forced-policy cohorts.
- Report constrained regret and disagreement clusters.

### Phase 6: reviewed activation

Activation remains a separate approval. It applies one axis at a time behind
an internal override and follows the existing acceptance and rollback
criteria.

## Delivery Roadmap

### Stage 0: preserve and finish the foundation

1. Keep the receive-credit axis and retained oversized-write selector as the
   reference implementations.
2. Finish multi-host correctness and provenance gates.
3. Resolve known instrumentation and platform-test limitations without
   changing policy behavior.
4. Review the existing seven-artifact planning bundle and this portfolio
   roadmap together.
5. Do not start a new production axis during this stage.

### Stage 1: send-path counterfactual library

Recommended order:

1. inventory and force `application_send_turn_planning`;
2. inventory and force `oversized_write_admission_quantum`;
3. define a named forced contract for `application_send_batch_formation`;
4. define a cap-only forced contract for `queued_send_burst_budget`; and
5. collect normal, constrained, and multi-architecture counterfactuals.

The purpose is a correct library and dataset, not immediate adaptation.

### Stage 2: actor and memory foundations

1. add bounded actor work/service observations;
2. define a real cross-stream and cross-connection fairness outcome;
3. design `actor_work_quantum`;
4. inventory buffer ownership/copy paths;
5. define memory-attributed outcomes; and
6. design conservative-only `adaptive_backpressure`.

### Stage 3: packet and receive efficiency

1. discover safe packet flush boundaries;
2. measure packet fill, packets per operation, crypto cost, and socket calls;
3. design `packet_flush_cadence`;
4. inventory receive delivery notifications and wake cost; and
5. design `receive_delivery_quantum` while receive credit remains fixed.

### Stage 4: placement and platform profiles

1. design connection-start shard placement;
2. retain platform capability cohorts;
3. evaluate datagram batching and buffer strategies across Windows, Linux x64,
   and Linux/macOS ARM64;
4. research crypto execution profiles; and
5. keep connection-start decisions immutable.

### Stage 5: protocol-sensitive research

Congestion/pacing, ACK behavior, and HTTP/3/QPACK require separate
architecture, requirement, verification, and campaign bundles. They do not
inherit activation authority from the transport scheduler work.

## Codex Work Protocol

For every future axis, Codex must follow this order.

### 1. Establish scope

- Read this roadmap and all linked canonical artifacts.
- State the one axis in scope.
- State every adjacent axis held at `legacy_current`.
- State whether the task is inventory, instrumentation, forced-policy
  implementation, campaign execution, offline analysis, shadow verification,
  or reviewed activation.
- Stop if the request would silently combine stages.

### 2. Inspect retained state

- Inspect the current worktree and branch.
- Preserve unrelated changes.
- Identify accepted work, unfinished candidates, and negative experiments.
- Record exact commits and evidence roots.
- Do not delete or silently incorporate a candidate.

### 3. Map authority

- Identify the correctness mechanism that owns the decision.
- Identify the proposed policy seam.
- List callers and consumers.
- List ownership, ordering, progress, resource, recovery, and terminal
  invariants.
- Identify repo, package, public API, and ProtocolLab boundaries.

### 4. Classify readiness

Answer:

- Is a stable seam present?
- Is the value forceable?
- Is shadow possible?
- Is the conservative value explicit?
- Is the safe boundary exact?
- Is the latch lifetime exact?
- Are observations bounded and available?
- Are outcomes attributable?
- Is rollback independently testable?

If any answer is no, produce the missing design or instrumentation slice
instead of implementing selection.

### 5. Define the axis contract

- Add stable axis and policy IDs.
- Keep `legacy_current` and `conservative` distinct.
- Define forced and shadow behavior.
- Define reason codes.
- Define snapshot/rule compatibility.
- Define fallback and out-of-domain behavior.
- Define the one safe application boundary.

### 6. Prove the mechanism first

- Add deterministic tests for every policy value.
- Prove correctness guards override forced values.
- Prove latching and transition behavior.
- Prove cancellation, disposal, terminal, and recovery behavior.
- Add property/fuzz coverage when state sequences are material.
- Run the narrowest affected requirement homes.

### 7. Prove instrumentation neutrality

- Build before testing.
- Measure disabled, observe-only, and shadow paths.
- Require bounded update cost.
- Require no steady-state managed allocation where the contract says none.
- Prove no stream enumeration or high-cardinality metric tags.
- Record missing and stale behavior.

### 8. Run forced counterfactuals

- Freeze binaries and hashes.
- Use permanent schemas.
- Alternate treatment order.
- Validate exact payloads.
- Capture target and generator pressure.
- Run sparse, target, neighboring, retained-negative, and bounded stress
  cohorts.
- Preserve every failed or noisy result.

### 9. Curate offline data

- Validate raw joins and checksums.
- Append exclusion reasons; never delete rows.
- Split by complete host and workload-family groups.
- Keep workload identity analysis-only.
- Stop model training when holdout diversity is insufficient.

### 10. Derive, do not deploy, rules

- Use interpretable offline analysis first.
- Convert candidate regimes to reviewed deterministic rules.
- Test feature leakage and threshold stability.
- Produce a versioned rule proposal and shadow plan.
- Do not update production constants from a notebook or one campaign.

### 11. Shadow

- Apply `legacy_current`.
- Require deterministic replay and reason codes.
- Compare to forced-policy cohorts.
- Investigate every correctness, high-regret, oscillation, missing, stale, and
  out-of-domain cluster.
- Clear the shadow exit gate before requesting activation review.

### 12. Activation and rollback

- Require explicit approval.
- Activate one axis only.
- Keep an internal force-legacy override.
- Re-run focused and full suites.
- Re-run local and reviewed ProtocolLab gates.
- Roll back immediately on a correctness trigger.
- Preserve the failure and rollback evidence as new immutable results.

### 13. Checkpointing

- Commit at safe, reviewable stopping points.
- Stage only the axis slice.
- Include exact verification results in the evidence ledger.
- Do not commit generated artifact trees unless their repository contract
  requires it.
- Push only when authorized by the active task and repository workflow.

## Definition Of Ready For An Axis

An axis is ready for implementation slicing only when:

- its owner and boundary are identified;
- its conservative and legacy values are explicit;
- at least two correct forceable implementations exist or can be introduced
  without changing public behavior;
- its latch lifetime is defined;
- correctness guards are enumerated;
- required observations have bounded ownership and cost;
- outcomes are attributable and schema-ready;
- negative evidence and adjacent axes are identified;
- a forced campaign can isolate it;
- rollback is defined; and
- trace and review homes exist.

## Definition Of Ready For Offline Analysis

An axis is ready for offline regime discovery only when:

- forced/applied values are proven;
- exact payload and correctness gates pass;
- target and generator health are retained;
- multiple repetitions exist;
- excluded rows retain explicit reasons;
- at least three independent host fingerprints and sufficient workload-family
  diversity exist for honest grouped holdouts;
- binaries and instrumentation are compatible within each cohort;
- outcomes include the constraints relevant to the axis; and
- the split manifest prevents connection/run leakage.

## Definition Of Ready For Shadow

An axis is ready for shadow only when:

- a reviewed deterministic rule version exists;
- the rule consumes only approved observations;
- missing, stale, saturated, contradictory, and out-of-domain behavior is
  deterministic;
- entry, leave, dwell, and fallback rules are explicit;
- replay is exact;
- shadow output has no production consumer; and
- counterfactual cohorts cover every recommendation class.

## Definition Of Ready For Active Review

An axis may request active-internal review only when:

- shadow clears its complete exit gate;
- force-legacy rollback is proven;
- correctness, latency, fairness, memory, and recovery constraints pass;
- held-out hosts and workloads support the rule;
- no unexplained transition or regret cluster remains;
- focused and full Release suites pass;
- a reviewed operator proposal names exact binaries, rules, schemas, hosts,
  commands, and remaining caveats; and
- activation remains limited to that one axis.

## Decisions Requiring Explicit Review

The following must not be guessed during implementation:

- the first axis after receive-credit foundation;
- whether one unified policy snapshot or seam-local snapshots are preferred;
- the first production epoch basis;
- the definition of useful actor work;
- the stream and connection fairness metric;
- application-visible backpressure behavior;
- whether runtime pressure advice is included in v1;
- which platform capabilities are supportable contracts;
- whether connection-start congestion or crypto profiles are ever exposed
  beyond internal configuration;
- whether HTTP/3 uses the transport controller substrate or a parallel
  component-local controller; and
- when enough independent hosts and workloads exist to begin model training.

## Recommended Next Review Decision

The July 25-26, 2026 experiment-control chain completed operation-correlated
evidence, reviewed actuation proofs, the approved batch/buffer correctness
interaction, and the bounded activation-qualified holdout extension for
`application_send_batch_formation` and `buffer_copy_coalescing`. The extension
closed the prior activation gap and concluded
`measurement_completed_no_stable_rule`. That result preserves the two values'
activation and correctness eligibility while declining to promote a selector.
`active_internal` and production behavior remain unauthorized.

The July 27-28 follow-up completed bounded canonical onboarding for
`oversized_write_admission_quantum` and `queued_send_burst_budget`,
independently reviewed their runtime-derived proofs, promoted
`single_fragment` and `single_datagram`, and preserved
`bounded_multi_fragment` as blocked on
`shadow_recommendation_value_mismatch`. The exact
`send_admission_composition` A0 through A7 matrix then passed correctness.
Factor-cell-space v3 now binds that reviewed eight-cell exhaustive subset to
family catalog v5 while retaining all four bounded cells as blocked.

The next reviewed decision is measurement execution scope, not another
authorization or a covering-array generator. The exact internal
`send_admission_composition_performance_v1` capability and deterministic
dry-run campaign are prepared, but timing execution remains false until a
host and workload scope are selected. Review must choose between a clearly
labeled local developer-host characterization and ProtocolLab rack execution,
then choose a four-cell pilot (`A0`, `A3`, `A4`, `A7`) or the full A0 through
A7 pilot. Covering arrays remain deferred until a future reviewed family has
at least 65 effective cells and a separately traced generator.

## Final Constraint

The adaptive runtime is a deterministic safety envelope around a library of
correct policy choices. It is not a self-optimizing transport and not an online
learning system. Offline analysis may discover useful regimes; only reviewed,
versioned, deterministic rules may influence new work, and every rule remains
subordinate to protocol correctness, progress, ownership, resource limits,
and rollback.

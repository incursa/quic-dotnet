# Adaptive Runtime Policy Planning

Status: planning checkpoint

Date: 2026-07-20

This document records the architecture direction for adaptive QUIC runtime
behavior after the July 2026 same-connection performance experiments. It is a
planning artifact, not authorization to promote the current receive-credit
candidate or to replace protocol invariants with performance heuristics.

The optimization loop pauses at this checkpoint. Preserve the accepted
adaptive oversized-write and read-dominant receive-credit work, all matched
evidence, and all retained negative experiments before beginning the broader
implementation plan described here.

## Problem Statement

One fixed scheduler policy is not consistently best across sparse,
multiplexed, receive-heavy, send-heavy, duplex, and saturated workloads. Stream
count is useful context, but it is not a sufficient selector:

- the current receive-credit candidate improved c16 download while regressing
  c16 upload;
- it improved c32 download while regressing c32 duplex;
- policies that help c16-c24 have previously regressed c1-c4 or c32+;
- merely open streams do not represent runnable or heavily used streams;
- queueing, flow-control headroom, loss, application consumption, and resource
  pressure can change after a connection is established.

The runtime therefore needs bounded, explainable policy adaptation based on
measured connection behavior. Adaptation must preserve QUIC correctness,
fairness, cancellation, disposal, flow control, congestion control, recovery,
and buffer ownership.

## Decisions

1. Keep one correctness-critical scheduler and expose independently selectable
   policy controls. Do not maintain unrelated full scheduler implementations
   unless a policy cannot be expressed through a stable seam.
2. Place the primary adaptive controller at the connection boundary. That is
   where congestion, recovery, connection flow control, packet construction,
   and stream coordination meet.
3. Do not put a global manager in the per-packet or per-stream hot path. A
   runtime-level advisor may publish coarse CPU, thread-pool, memory, and socket
   pressure snapshots to connection controllers.
4. Do not evaluate policy for every packet. Aggregate inexpensive counters in
   existing actor work and evaluate only at bounded connection-safe points.
5. Support adaptation in both directions, with hysteresis and minimum dwell
   times. Do not oscillate between policies as individual queues briefly drain.
6. Latch decisions that affect ownership, fragmentation, completion, or
   ordering for the lifetime of the admitted operation. A later controller
   decision applies only at a safe boundary.
7. Keep a conservative baseline policy that can be forced for diagnosis and
   used as the fail-safe when evidence is missing, contradictory, or stale.
8. Use machine learning offline to discover interactions and boundaries. The
   production runtime initially consumes reviewed deterministic rules, not an
   opaque model and not online exploration.

## Proposed Control Hierarchy

### Runtime pressure advisor

The runtime advisor samples process-wide conditions at low frequency and
publishes immutable snapshots. It does not enumerate streams or make
connection-specific decisions.

Candidate inputs include:

- process CPU utilization and available processor count;
- thread-pool queue delay and starvation indicators;
- managed allocation and GC pressure;
- socket-send completion delay or sustained send backlog;
- global pooled-buffer bytes and configured memory bounds.

These inputs are advisory. A connection must remain correct and make progress
when the advisor is absent, delayed, or disabled.

### Per-connection adaptive controller

Each connection owns its observation state and current policy selections. The
controller reads counters already maintained by the connection actor and
changes policy only at an actor-safe boundary.

The controller should not centralize stream data or add a lock around normal
stream operations. Its output is a compact policy snapshot consumed by the
existing scheduler and flow-control paths.

### Stream-local behavior

Streams retain independent queues, completion state, cancellation, and
disposal. Stream-local code may read a latched policy decision, but it does not
query a central controller for every read, write, frame, or packet.

## Policy Axes

Treat the following as orthogonal controls where the implementation permits:

- receive-credit publication: immediate, threshold-batched, or conservative
  duplex cadence;
- oversized-write admission quantum per actor turn;
- application-send batching quantum;
- maximum consecutive work per runnable stream;
- ready-stream selection and fairness quantum;
- actor wakeup coalescing and maximum work per wake;
- packet flush cadence within existing congestion and pacing budgets;
- backpressure thresholds within existing byte and ownership bounds.

Avoid naming production modes after benchmark scenarios such as `upload`,
`download`, or `c16`. Those labels are unavailable to the transport and would
overfit the current harness. Policies must be selected from observable runtime
conditions.

## Observation Model

Prefer normalized signals that transfer across payload sizes, machines, and
connection speeds:

- open, active, runnable, receive-active, and send-active stream counts;
- inbound and outbound byte-rate exponentially weighted moving averages;
- bytes and operations per active stream;
- queued work by type, queue delay, and service time;
- queue-delay-to-service-time ratio;
- actor turns and useful work completed per wake;
- stream-write completion latency;
- receive-window headroom and estimated time until flow-control exhaustion;
- time and bytes since the last credit publication;
- stream- and connection-flow-control blocked duration;
- outbound application backlog and delayed-send duration;
- packet fill, packets per logical operation, and control-frame ratio;
- loss, retransmission, PTO, and ACK pressure;
- outstanding pooled buffers and bytes;
- coarse runtime advisor snapshot.

Instrumentation must be allocation-free or sampled outside the hot path.
Disabled instrumentation must be proven neutral with same-binary or matched
frozen-binary evidence.

## Evaluation Cadence

Use a hybrid of event-triggered and periodic evaluation:

- actor work updates counters without invoking the controller;
- threshold crossings request one coalesced evaluation at the next safe actor
  boundary;
- while a connection is active, a coarse periodic evaluation prevents a stale
  policy when no threshold fires;
- while quiescent, evaluation stops or falls back to a much slower heartbeat;
- critical correctness conditions bypass policy and immediately publish credit
  or make progress.

Initial experiments should compare active evaluation intervals in the
250-500 ms range and an idle fallback near five seconds. These are planning
starting points, not production constants. An RTT- or work-normalized epoch may
prove more transferable than wall-clock time.

An evaluation must remain substantially cheaper than one normal actor turn.
Benchmark the decision function independently and measure evaluations per
second in end-to-end runs.

## Transition Rules

- Use separate enter and leave thresholds.
- Require sustained evidence across multiple epochs before promotion.
- Require a longer quiet period before demotion when ownership or queue shape
  would otherwise churn.
- Apply changes only to new work when an in-flight operation has latched
  fragmentation, batching, completion, or ownership behavior.
- Force conservative progress when available credit is low, the peer reports
  blocking, FIN or shutdown is pending, cancellation or disposal begins, or
  recovery requires immediate action.
- Bound every queue and retained buffer independently of the selected policy.
- Record a reason code and epoch for every transition in diagnostic mode.

## Offline Experiment And Learning Plan

### Forced-policy campaigns

Every policy control must support a test-only forced setting. Run the same
workload under each eligible policy combination so the dataset contains a real
counterfactual instead of assuming the policy chosen online was optimal.

Campaign dimensions should include:

- 1 KiB, 64 KiB, and 1 MiB payloads;
- fixed-total and fixed-per-stream workloads;
- upload, download, duplex, request/response, and streaming shapes;
- one and multiple connections;
- c1, c4, c8, c16, c24, c32, c64, and stress cardinalities where healthy;
- sparse, bursty, sustained, and stream-churn arrival patterns;
- controlled loss, delay, receive-window, and application-consumption rates;
- varied CPU availability and target/generator pressure;
- Incursa baseline and relevant peer controls.

Use exact payload validation, deterministic interleaving, frozen binaries,
multiple repetitions, host-pressure recording, and workload-level holdouts.

### Dataset shape

One training row should represent a bounded connection epoch, not one packet.
It should contain:

- pre-decision observations;
- forced policy selections;
- transition and dwell state;
- throughput, latency, allocation, fairness, queue, loss, and memory outcomes;
- correctness and timeout outcomes;
- host and binary provenance;
- workload identity retained for analysis but excluded from production rules.

The optimization target is constrained and multi-objective. A policy is not a
winner if it improves throughput while violating correctness, memory bounds,
fairness, or accepted latency guardrails.

### Model use

Start with interpretable techniques:

- decision and regression trees;
- generalized additive models;
- interaction and change-point analysis;
- clustering for discovering operating regimes;
- feature importance and partial-dependence review.

Train on forced-policy outcomes, validate on workloads and machines withheld
from training, then distill useful boundaries into reviewed deterministic
rules. Do not deploy a model merely because it predicts the training campaign.

If deterministic rules later prove inadequate, a small versioned inference
model may be considered only with deterministic fallback, bounded execution
cost, explainable decisions, adversarial-input review, and complete rollback.
Online reinforcement learning or production exploration is out of scope.

## Shadow And Promotion Process

1. Run the controller in shadow mode and record what it would select.
2. Compare shadow selections with forced-policy counterfactual evidence.
3. Enable one policy axis at a time behind an internal override.
4. Validate sparse, target, neighboring, and stress regimes.
5. Run focused correctness, transition, cancellation, disposal, flow-control,
   congestion-control, recovery, and fairness tests.
6. Run the full regression suite.
7. Use ProtocolLab only after matched local evidence clears the local gate.
8. Preserve rejected rules and datasets so later work does not repeat them.

The conservative policy remains the default whenever the controller lacks
enough observations or detects contradictory, unstable, or out-of-domain
conditions.

## Current Checkpoint

The accepted adaptive oversized-write quantum remains valid retained work. Its
strongest matched local results included c16 download and duplex improvements
and c24 upload and download improvements while keeping its c1-c4 policy path
disabled. Its remaining tail-latency caveats are already recorded in
`docs/performance-improvement-wishlist.md`.

The receive-credit candidate was subsequently narrowed and accepted as a
read-dominant policy. The final selector requires at least 16 live streams and
permanently falls back to immediate credit after the connection issues any
application data. This preserves upload/download gains while the final c16
duplex guardrail remained neutral. Half-window and quarter-window policies that
reactivated during duplex traffic are retained negatives because they improved
aggregate throughput at the cost of unacceptable tail latency. Exact metrics,
hashes, tests, and evidence paths are recorded in
`docs/performance-improvement-wishlist.md`.

Do not widen the receive-credit policy or derive additional adaptive rules from
these measurements without a new bounded plan. Repeated campaigns must continue
to distinguish policy effects from host regimes and must preserve the sticky
duplex fallback.

Retained evidence roots include:

- `C:\shared\temp\quic-adaptive-write-quantum-20260720`;
- `C:\shared\temp\quic-cardinality-common-20260720`;
- `C:\shared\temp\quic-flow-credit-cadence-20260720`;
- the negative-evidence roots referenced by
  `docs/performance-improvement-wishlist.md`.

## Planning Deliverables For The Next Work Period

Before new runtime optimization, produce and review:

1. A policy seam inventory showing existing controls, ownership, hot-path cost,
   and whether each can be forced in tests.
2. A connection observation schema with update cost and sampling ownership for
   every signal.
3. A controller state machine covering promotion, demotion, hysteresis,
   latching, fallback, shutdown, and out-of-domain behavior.
4. A permanent local campaign plan and machine-readable result schema.
5. A dataset and provenance contract suitable for offline analysis.
6. A shadow-mode verification plan.
7. Explicit acceptance and rollback criteria for the first adaptive policy.

No additional production policy axis should begin until these planning
artifacts are coherent enough to review together.

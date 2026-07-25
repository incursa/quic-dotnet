# Adaptive Runtime Stage 2 Actor And Memory Foundation

Status: actor observation foundation in progress;
`buffer_copy_coalescing` is internally forceable; no Stage 2 policy is active

## Purpose

This document defines the first Stage 2 slice from the approved adaptive
runtime policy-axis roadmap. It establishes bounded actor-service evidence and
the gates that must be satisfied before `actor_work_quantum`,
`ready_stream_fairness`, `buffer_copy_coalescing`, or
`adaptive_backpressure` can become forceable policy axes.

The Stage 1 send-path axes and `buffer_copy_coalescing` remain implemented and
independently forceable. A
campaign may still vary only one axis, receive-credit publication remains
`legacy_current`, and every adjacent applied policy remains
`legacy_current`. The buffer seam does not authorize a tuned threshold,
controller input, `active_internal` mode, or production behavior.
The checkpoint status of every roadmap axis is maintained in
[`adaptive-runtime-policy-axis-implementation-matrix.md`](adaptive-runtime-policy-axis-implementation-matrix.md);
that matrix does not replace or weaken the approved roadmap.

## Existing Actor Seam

`QuicConnectionRuntimeShard` owns one unbounded multi-producer,
single-consumer inbox and one deadline scheduler. The current consumer:

1. enqueues due timer entries;
2. drains connection work already available to the single reader;
3. performs a bounded same-connection packet lookahead for ACK finalization;
4. executes one complete `QuicConnectionRuntime` transition per dequeued work
   item;
5. applies the transition's effects;
6. performs inline application-send, flow-control, and stream-capacity
   follow-on work;
7. samples diagnostic runtime pressure; and
8. waits for either new inbox work or the next deadline wake.

The current loop drains available work. It has no stable maximum-work policy,
no connection-level remaining-work contract, and no reviewed preemption point
inside a transition or effect loop. A behavior-neutral exactly-once repost
primitive now exists, but it is deliberately disconnected from the shard
until those remaining gates can drive it safely. Therefore an actor quantum
cannot yet be applied.

The existing `QuicMetrics` instruments aggregate queue delay, service time,
wake cycles, work items per wake, packet runs, and follow-on flush counts.
Those measurements are useful diagnostics but do not by themselves provide a
versioned, connection-attributable, replayable evidence contract.

## Observation-Only Runtime Contract

`QuicActorServiceObservationMode` has the closed values:

- `Disabled`;
- `ObserveOnly`.

There is deliberately no forced, shadow, or active value yet. A connection
may enable `ObserveOnly` only with an `IQuicActorServiceEvidenceSink`.
Supplying a sink while disabled or enabling observation without a sink is a
configuration error. Sink return values and exceptions are diagnostic-only
and cannot affect transition, effect, timer, ownership, or disposal behavior.

The current observation contract is
`quic-actor-service-observation-v5`. The provenance contract is
`quic-actor-service-provenance-v5`. Retained v1 through v4 observation and
provenance contracts remain immutable.

One observation describes one shard dispatch of one connection work item and
contains:

- a connection-local monotonic service sequence;
- shard-local wake sequence and position;
- bounded wake completion and source;
- a closed work kind;
- a bounded completion, skip, or fault disposition;
- queue delay when an enqueue timestamp exists;
- connection-local inter-service gap after the first observed dispatch;
- scheduled timer lateness when the work item came from the shard deadline
  scheduler;
- exact shard-wide posted-or-servicing connection-contender count at service
  start when the accounting state is valid;
- complete transition-plus-effect service duration;
- pending work-item count after dequeue;
- emitted effect count;
- application-send, flow-control, and stream-capacity follow-on counts;
- lifecycle phase after service;
- disposal state; and
- explicit validity flags.

The closed work kinds are:

- connection event;
- timer;
- packet received;
- stream-capacity release;
- flow-control credit update;
- stream open;
- stream write.

The record never contains scenario name, payload label or constant,
requested concurrency, peer identity, URL, application identity, stream
identity, application data, packet bytes, or buffer contents.

## Wake Semantics

A wake sequence is local to one shard process. Sequence one represents
consumer start. Later values identify a return from the inbox wait.
`wakeCompletion` distinguishes consumer start, synchronous completion, and
asynchronous completion. `wakeSource` distinguishes consumer start, ordinary
inbox work, and a recognized deadline wake.

The record's wake position counts productive connection work items within the
observed wake. Empty wakes remain available only through the existing bounded
aggregate metric. A dataset may claim complete wake membership only when its
run manifest proves that actor observation covered every connection on the
shard for the entire interval. Otherwise wake grouping is partial and must be
classified accordingly.

Wake sequence is provenance, not a controller feature. A connection-local
controller may later consume a coarse immutable shard-pressure snapshot, but
it may not inspect another connection's private identity or state.

## Useful Actor Work Units

Stage 2 does not collapse actor work into one unreviewed event count. The
initial useful-work representation is a bounded vector:

- one dequeued connection dispatch;
- dispatch kind;
- emitted effects;
- application-send follow-on items;
- flow-control follow-on items;
- stream-capacity follow-on items;
- service duration; and
- queue delay.

The vector preserves unlike costs instead of claiming that one packet, one
large write, one timer, and one credit flush are equivalent. A future
`actor_work_quantum` proposal must define cooperative safe checkpoints inside
the expensive kinds before it can convert the vector into a cap or immutable
plan.

`UsefulWorkUnitsUndefined` remains set in observation version 4. Removing that
flag requires a reviewed observation-version change, deterministic mechanism
tests, and evidence that the proposed unit predicts service cost across
packet, API, timer, recovery, and terminal work without workload identity.

`quic-actor-useful-work-vector-v1` formalizes this representation in
`QuicActorUsefulWorkVector`. It preserves exactly one dispatch plus the closed
work kind, effect count, three follow-on counts, service duration, and optional
queue delay. It is intentionally not the sum of those fields and does not
define a threshold, cap, controller input, or policy value.

## Exact Accepted-Dispatch Backlog

Actor observation v4 adds
`AcceptedConnectionWorkItemsAfterCurrent`. The value is captured from the
connection-local accepted shard-work counter before the current work item
completes its accounting lifetime. A valid value is exactly the number of
already accepted work items for that connection after the current dispatch:
zero means no later accepted dispatch exists; a positive value means that
many later accepted dispatches exist.

This is an O(1) accepted-dispatch backlog. It is not a claim that any internal
send, retransmission, flow-control, stream-capacity, timer, recovery, or
terminal queue is immediately runnable. It cannot drive a continuation
repost, establish continuous runnable time, or prove fairness. Invalid or
saturated accounting produces a null value and explicit
`MissingAcceptedConnectionWorkItemsAfterCurrent` validity.

The v4 epoch summary records observation coverage, total, maximum, and turns
with a positive accepted-dispatch backlog. Raw export validation recomputes
all four values from the exact actor range. This closes the no-scan signal for
already accepted dispatches only; a future preemptible operation must own a
separate exact continuation-ready signal.

The reviewed cooperative boundary for this slice is the existing return from
one complete shard work item, after its transition, effects, follow-on
measurement, actor evidence, owned resource release, post-service publication,
and contender-accounting completion. Transition interiors, effect iteration,
ACK lookahead pairs, datagram handoff, recovery, terminal work, and ownership
release are non-preemptible until separately designed.

## Exact Internal Continuation Assessment

Actor observation v5 adds
`quic-actor-continuation-assessment-v1`. The fixed connection-local record
assesses application-send, flow-control-credit, and stream-capacity follow-on
producers independently. Each producer has one closed state:

- `NotAssessed`: this dispatch did not run the producer;
- `Drained`: the producer ran and no internal items remain;
- `Scheduled`: items remain, but an existing owned deadline rather than an
  immediate continuation owns later progress;
- `Blocked`: items remain but an authoritative congestion, pacing, recovery,
  flow-control, path, terminal, or ownership guard prevents immediate work;
- `ReadyAfterCooperativeYield`: a reviewed preemptible operation yielded at a
  safe boundary with exact immediately resumable work; or
- `Invalid`: exact state cannot be established.

`NotAssessed` and `Invalid` require a null remaining count. `Drained` requires
zero. `Scheduled`, `Blocked`, and `ReadyAfterCooperativeYield` require a
positive bounded remaining count. Contradictory pairs fail validation.
Incomplete and invalid assessment remain explicit validity flags.

The legacy runtime currently emits `Drained`, `Scheduled`, `Blocked`, or
`NotAssessed` as applicable. No production path emits
`ReadyAfterCooperativeYield`. That value is reserved for a later reviewed
cooperative checkpoint, so a queued item, accepted dispatch, or blocked item
cannot be silently relabeled continuation-ready.

The v5 epoch summary retains complete-assessment coverage and per-producer
observation, drained, scheduled, blocked, ready-after-yield, and maximum
remaining counts. Raw export recomputes these fields from exact
`source + connectionKey + serviceSequence` membership. The assessment changes
no timer ownership, retry rule, queue order, scheduling, or policy application
and remains disconnected from the repost gate.

## Exactly-Once Continuation Repost Primitive

`QuicActorContinuationRepostGate` is a connection-local behavior-neutral
ownership primitive. It packs one monotonic generation and one closed state
into a single atomic value. It has no queue reference, callback, protocol
state, timer, model, threshold, or policy lookup.

The closed states are:

- `Idle`: no continuation token is posted or in service;
- `Posted`: exactly one caller owns enqueue of the current token;
- `Servicing`: the exact current token is executing;
- `RepostRequested`: the current token is executing and one or more concurrent
  requests have coalesced into a single required follow-on; and
- `Stopped`: no later request, begin, or completion can create work.

The transition contract is:

1. `Idle -> Posted` increments the generation and returns the only token whose
   caller may enqueue that generation.
2. Another request while `Posted` is already represented and cannot create a
   second enqueue owner.
3. `Posted -> Servicing` requires the exact nonempty generation token.
4. A request while `Servicing` atomically changes the state to
   `RepostRequested`; further requests coalesce.
5. At a reviewed safe boundary, completion changes `Servicing` to `Idle` when
   no exact remaining work exists.
6. Completion changes `Servicing` or `RepostRequested` to one new `Posted`
   generation when exact remaining work or a concurrent request exists.
7. An enqueue owner that cannot post must abandon the exact `Posted` token,
   which changes the gate to `Stopped`. Returning to `Idle` would be unsafe
   because another requester may already have coalesced with the failed post.
8. Cancellation, disposal, shutdown, or terminal teardown may stop the gate
   from any state. Stale, duplicate, empty, or mismatched tokens cannot change
   state.

This closes the token-ownership and lost-request state-machine design; it does
not close the actor quantum. The shard does not instantiate or call the gate.
An exact continuation-ready producer for preempted internal work,
enqueue-failure owner, timer priority, terminal bypass, and buffer ownership
across yield remain required before integration. The accepted-dispatch
backlog does not satisfy that continuation-ready contract.

## Epoch Aggregation

`QuicActorServiceEpochAccumulator` consumes observation records and produces
`quic-actor-service-epoch-v5` summaries. Retained v1 through v4 summaries
remain immutable. Version 4 retains only bounded scalar state:

- first and last service sequence;
- total, completed, skipped, and faulted turns;
- counts for every closed work kind;
- observed wake count and maximum wake position;
- service total, maximum, and integer EWMA;
- queue-delay observation count, total, maximum, and integer EWMA;
- inter-service-gap observation count, total, maximum, and integer EWMA;
- scheduled deadline-lateness observation count, total, maximum, and integer
  EWMA;
- service-contender observation count, maximum, and the number of observed
  turns whose count was greater than one;
- accepted-connection-work observation count, total, maximum, and turns with
  a positive after-current value;
- complete continuation-assessment turns plus per-producer observation,
  drained, scheduled, blocked, ready-after-yield, and maximum-remaining
  counts;
- maximum pending work-item count after dequeue;
- total effects;
- three follow-on totals; and
- the union of validity flags.

Capture resets the accumulator. An empty capture remains explicitly empty.
All additions saturate, and saturation remains visible. The accumulator uses
no dictionary, stream scan, global lock, policy lookup, model, or unbounded
collection.

The former Stage 1 epoch callback occurred before complete actor service,
effect work, follow-on measurement, actor observation, and work-item resource
release. `adaptive-runtime-post-service-boundary-v1` now defines the exact
replacement export boundary. Hosted-shard publication occurs after actor
observation and resource release. Independent-consumer publication occurs
after connection-event resource release. Each boundary repeats the connection
epoch sequence and end tick, names its execution source, records disposition,
actor-observation publication, resource-release completion, and explicit
fault or missing validity.

`QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator` accepts all four Stage 1
axis evidence streams plus actor-service and buffer-copy observations. It
seals fixed Stage 1, actor, and buffer summaries only when the versioned
post-service callback supplies an exactly matching connection observation,
receive-credit snapshot, and boundary. The deterministic join requires equal
connection epoch sequence and epoch end tick. A mismatched, duplicate,
out-of-order, or nonpositive epoch is rejected before any accumulator resets.
The joined record is
`adaptive-runtime-unified-epoch-evidence-v7`; retained v1 through v6 rows
remain immutable. Version 7 retains actor v5 and adds the configured
`buffer_copy_coalescing` snapshot plus v4 legal/applied buffer outcomes.

The raw QUIC harness now configures the same unified accumulator as every
relevant connection-local evidence sink whenever an adaptive execution is
requested. It writes one
`adaptive-runtime-unified-epoch-raw-v7` wrapper per sealed epoch while
retaining the earlier receive-credit and Stage 1 compatibility streams.
The append-only exporter retains source hashes, raw rows, validation summary,
and manifest; checks exact monotonic joins and one varied axis; and preserves
bounded-channel failures as explicit `invalid_contract` evidence. Command,
binary, host, workload, classification, and checksum inventory remain the
campaign runner's provenance layer and are not accepted from runtime inputs.

## Explicitly Missing V5 Inputs

The shard cannot yet provide the following honestly at connection scope:

- runnable connection count;
- oldest shard item age;
- reviewed scalar useful-work units.

Every v4 record marks the remaining inputs missing. Queue delay for a work
item is not relabeled as oldest shard item age. Pending inbox depth is not
relabeled as runnable connection count. Inter-service gap is not relabeled as
continuous runnable time or starvation. Event count is not relabeled as a
useful-work quantum. The posted-or-servicing contender count is not relabeled
as runnable state, continuous runnable time, starvation, or fairness.
Accepted connection work after the current dispatch is not relabeled as an
internal continuation-ready or runnable signal.
Likewise, `Scheduled` and `Blocked` continuation assessments do not establish
runnable work. Only `ReadyAfterCooperativeYield` may do so, and the current
runtime emits no such state.

The shard deadline scheduler already owns the exact scheduled due tick. The
timer work item now retains that tick in an existing inactive storage slot and
records nonnegative lateness at actor service start. Timer work posted through
another path without scheduler provenance remains explicitly missing;
non-timer work treats deadline lateness as not applicable rather than missing.
This observation does not change timer order, wake behavior, or priority.

The connection runtime atomically exchanges the previous observed service
start timestamp and records the elapsed gap after the first dispatch. This is
a connection-local service-cadence precursor only. It cannot establish that a
connection stayed runnable throughout the gap, which other connections were
runnable, or whether starvation occurred.

## Actor-Quantum Safety Gate

Before `actor_work_quantum` becomes forceable, architecture and verification
must define and prove:

- a cooperative safe boundary for each preemptible work kind;
- the exact remaining-work signal without enumerating unbounded queues;
- integration of the proven generation-token repost gate;
- no lost wakeup between exact remaining-work publication and repost;
- no duplicate enqueue or service of a repost generation;
- timer and deadline priority;
- recovery, probe, ACK, credit, cancellation, disposal, close, and terminal
  bypass rules;
- complete shutdown drain;
- inline completion behavior;
- buffer ownership across a yield;
- cross-connection service-gap and starvation outcomes; and
- disabled and force-legacy parity.

Until those gates pass, the only applied actor behavior is
`legacy_current`.

## Fairness Outcome Foundation

Cross-connection fairness must use complete shard coverage and
workload-neutral measures. The initial review candidates are:

- maximum and percentile time between services while a connection remains
  runnable;
- maximum queue delay by bounded work kind;
- share of shard service duration during overlapping runnable intervals;
- starvation count for a connection that remains runnable across reviewed
  timer or service bounds;
- timer lateness while other connections receive service; and
- progress counts for recovery and terminal work.

Per-stream fairness remains a separate `ready_stream_fairness` axis. Stream
identity cannot be a production controller input. Dataset-only pseudonymous
keys may be used after bounded state cost, close/reset cleanup, and
priority-inversion guards are reviewed.

## Buffer And Backpressure Boundary

This foundation does not select actor work, ready-stream fairness, retention,
or backpressure behavior. The reviewed buffer inventory maps every managed
owner used by the first combined-send coalescing seam.

That implementation inventory is now recorded in
[`adaptive-runtime-stage2-buffer-ownership-copy-inventory.md`](adaptive-runtime-stage2-buffer-ownership-copy-inventory.md).
It now defines `legacy_current` and the lower-only
`memory_conservative` two-source-segment cap at the post-Stage 1 combined-send
boundary under `REQ-QUIC-CRT-0190`. The broader observation foundation records
existing send-side copy and retention paths, owned path-migration
retransmission clones, and receive-segment construction or capacity reuse
under `REQ-QUIC-CRT-0182`. The `REQ-QUIC-CRT-0185` checkpoints carry
compact lifetime tokens through receive-segment partial reads and
flow-control retry request ownership. They record exact delivery/reset and
replacement/downstream-copy/completion/cancellation/terminal releases after
the authoritative pool return. Terminal-release correlation for every other
observed owner, copy-scope retained age, and pool outstanding remain explicit
gaps.

`adaptive_backpressure` remains conservative-only and separately reviewable.
It may eventually lower an admission cap below an authoritative hard bound.
It may never raise a hard bound or delay progress, recovery, credit,
cancellation, disposal, or terminal work.

## Verification

The exact accounting foundation for later complete-shard evidence is
`REQ-QUIC-CRT-0187`. It counts a connection once while it has one or more
accepted posted-or-servicing shard work items. Acceptance uses one compact
work-item flag; enqueue rejection, normal post-service completion, resource
release, cancellation, disposal, and shutdown drain close the count. The
work-item remains 144 bytes. Actor observation v4 emits the exact count at
service start and exact accepted connection work after current when valid;
actor epoch v4 aggregates both signals. Missing, invalid, and saturated state
remains explicit.
The evidence is not a runnable-connection, continuous-runnable, starvation,
fairness, or controller-input claim.

Requirement homes `REQ-QUIC-CRT-0181`, `REQ-QUIC-CRT-0183`, and
`REQ-QUIC-CRT-0184` verify:

- exact observe-only mode and sink pairing;
- one versioned record per observed shard dispatch;
- bounded work, wake, disposition, lifecycle, and validity values;
- connection-local monotonic service sequence;
- schema-valid observation and epoch records;
- semantic count and sequence validation;
- bounded epoch accumulation and reset;
- follow-on attribution;
- exact scheduled timer lateness without changing timer priority;
- connection-local inter-service gap without a runnable or starvation claim;
- exact posted-or-servicing service-contender capture and aggregation without
  a runnable or fairness claim;
- exact accepted connection work after the current dispatch without an
  internal continuation-ready claim;
- unchanged compact shard work-item size; and
- sink-failure neutrality;
- hosted post-service ordering after actor observation and resource release;
- versioned source, disposition, actor-publication, release, and fault state;
- exact connection-observation, receive-credit, and boundary join keys;
- rejection before reset for an invalid join; and
- schema-valid boundary and unified evidence records;
- one permanent raw row containing receive credit, all four Stage 1 axes,
  actor service, and buffer-copy summaries;
- one separate sample-scoped raw record for every observed actor dispatch,
  joined by exact source-scoped `connectionKey + serviceSequence` membership
  in the epoch summary range;
- exact connection-local join, ordering, duplicate, and one-varied-axis
  validation;
- append-only raw, validation, manifest, source hash, and count retention; and
- explicit missing, duplicate, orphan, out-of-order, and export-failure
  retention or rejection with invalid-contract classification;
- separate schema-valid buffer construction and terminal-release raw records
  with exact `connectionKey + operationSequence` joins; and
- receive-segment delivery/reset and application-write-request lifecycle
  release plus throwing/rejecting sink neutrality.

Existing shard, deadline, receive-buffer ownership, work-item layout, metrics,
and stream-capacity homes remain authoritative. Performance measurements stay
outside correctness CI.

## Remaining Stage 2 Order

1. Complete runnable-state, complete-shard coverage, and fairness observations
   without relabeling inbox depth or inter-service gap as continuous runnable
   connection state.
2. Add a reviewed cooperative yield site that can truthfully produce
   `ReadyAfterCooperativeYield`; the accepted-dispatch backlog and v1
   continuation assessment cannot substitute for that proof.
3. Integrate the proven generation-token repost gate only after timer,
   recovery, cancellation, disposal, terminal, and ownership tests exist.
4. Design and force `actor_work_quantum` only after the safety gate.
5. Preserve the forceable `buffer_copy_coalescing` seam and its exact
   force-legacy rollback while measurement remains frozen.
6. Review conservative-only `adaptive_backpressure` application-visible
   behavior.

No large adaptive dataset transform or ML analysis begins before these
architecture foundations are complete. No active behavior is authorized.

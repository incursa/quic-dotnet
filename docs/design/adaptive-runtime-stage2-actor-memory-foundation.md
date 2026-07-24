# Adaptive Runtime Stage 2 Actor And Memory Foundation

Status: observation foundation in progress; no actor or memory policy is active

## Purpose

This document defines the first Stage 2 slice from the approved adaptive
runtime policy-axis roadmap. It establishes bounded actor-service evidence and
the gates that must be satisfied before `actor_work_quantum`,
`ready_stream_fairness`, `buffer_copy_coalescing`, or
`adaptive_backpressure` can become forceable policy axes.

The Stage 1 send-path axes remain implemented and independently forceable. A
campaign may still vary only one axis, receive-credit publication remains
`legacy_current`, and every adjacent applied policy remains
`legacy_current`. Stage 2 observation does not authorize a new treatment,
threshold, controller input, `active_internal` mode, or production behavior.

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
no exactly-once repost token, no connection-level remaining-work contract, and
no reviewed preemption point inside a transition or effect loop. Therefore an
actor quantum cannot yet be applied safely.

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

The observation contract is
`quic-actor-service-observation-v1`. The provenance contract is
`quic-actor-service-provenance-v1`.

One observation describes one shard dispatch of one connection work item and
contains:

- a connection-local monotonic service sequence;
- shard-local wake sequence and position;
- bounded wake completion and source;
- a closed work kind;
- a bounded completion, skip, or fault disposition;
- queue delay when an enqueue timestamp exists;
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

The v1 record never contains scenario name, payload label or constant,
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

`UsefulWorkUnitsUndefined` remains set in observation version 1. Removing that
flag requires a reviewed observation-version change, deterministic mechanism
tests, and evidence that the proposed unit predicts service cost across
packet, API, timer, recovery, and terminal work without workload identity.

## Epoch Aggregation

`QuicActorServiceEpochAccumulator` consumes observation records and produces
`quic-actor-service-epoch-v1` summaries. It retains only bounded scalar state:

- first and last service sequence;
- total, completed, skipped, and faulted turns;
- counts for every closed work kind;
- observed wake count and maximum wake position;
- service total, maximum, and integer EWMA;
- queue-delay observation count, total, maximum, and integer EWMA;
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
`adaptive-runtime-unified-epoch-evidence-v1`.

The raw QUIC harness now configures the same unified accumulator as every
relevant connection-local evidence sink whenever an adaptive execution is
requested. It writes one
`adaptive-runtime-unified-epoch-raw-v1` wrapper per sealed epoch while
retaining the earlier receive-credit and Stage 1 compatibility streams.
The append-only exporter retains source hashes, raw rows, validation summary,
and manifest; checks exact monotonic joins and one varied axis; and preserves
bounded-channel failures as explicit `invalid_contract` evidence. Command,
binary, host, workload, classification, and checksum inventory remain the
campaign runner's provenance layer and are not accepted from runtime inputs.

## Explicitly Missing V1 Inputs

The shard cannot yet provide the following honestly at connection scope:

- runnable connection count;
- oldest shard item age;
- deadline lateness;
- reviewed scalar useful-work units.

Every v1 record marks those inputs missing. Queue delay for a work item is not
relabeled as oldest shard item age. Pending inbox depth is not relabeled as
runnable connection count. Timer service is not relabeled as deadline
lateness. Event count is not relabeled as a useful-work quantum.

## Actor-Quantum Safety Gate

Before `actor_work_quantum` becomes forceable, a separate architecture and
verification checkpoint must define and prove:

- a cooperative safe boundary for each preemptible work kind;
- the exact remaining-work signal without enumerating unbounded queues;
- an exactly-once connection repost token;
- no lost wakeup between remaining-work publication and repost;
- no duplicate repost during concurrent producers;
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

This slice does not select a copy, segment, coalescing, retention, or
backpressure strategy. The next inventory must map every owner, rent, copy,
segment, crypto reference, socket reference, completion, cancellation, and
return path before `buffer_copy_coalescing` is forceable.

That implementation inventory is now recorded in
[`adaptive-runtime-stage2-buffer-ownership-copy-inventory.md`](adaptive-runtime-stage2-buffer-ownership-copy-inventory.md).
It confirms that only `legacy_current` is presently a real policy value and
defines the bounded observation and maintained-retention work required before
a conservative value can be implemented honestly. The first observation-only
slice now records five existing send-side copy and retention paths under
`REQ-QUIC-CRT-0182`; terminal release, retained age, pool outstanding,
retransmission clones, and receive segments remain explicit gaps.

`adaptive_backpressure` remains conservative-only and separately reviewable.
It may eventually lower an admission cap below an authoritative hard bound.
It may never raise a hard bound or delay progress, recovery, credit,
cancellation, disposal, or terminal work.

## Verification

Requirement homes `REQ-QUIC-CRT-0181`, `REQ-QUIC-CRT-0183`, and
`REQ-QUIC-CRT-0184` verify:

- exact observe-only mode and sink pairing;
- one versioned record per observed shard dispatch;
- bounded work, wake, disposition, lifecycle, and validity values;
- connection-local monotonic service sequence;
- schema-valid observation and epoch records;
- semantic count and sequence validation;
- bounded epoch accumulation and reset;
- follow-on attribution; and
- sink-failure neutrality;
- hosted post-service ordering after actor observation and resource release;
- versioned source, disposition, actor-publication, release, and fault state;
- exact connection-observation, receive-credit, and boundary join keys;
- rejection before reset for an invalid join; and
- schema-valid boundary and unified evidence records;
- one permanent raw row containing receive credit, all four Stage 1 axes,
  actor service, and buffer-copy summaries;
- exact connection-local join, ordering, duplicate, and one-varied-axis
  validation;
- append-only raw, validation, manifest, source hash, and count retention; and
- explicit export-failure retention and invalid-contract classification.

Existing shard, deadline, receive-buffer ownership, work-item layout, metrics,
and stream-capacity homes remain authoritative. Performance measurements stay
outside correctness CI.

## Remaining Stage 2 Order

1. Carry compact copy-lifetime tokens through every observed owner and record
   exact terminal release without object identity or an outstanding-operation
   dictionary.
2. Complete actor service, wake, follow-on, timer-lateness, runnable-state, and
   fairness observations.
3. Review useful-work units and exactly-once repost ownership.
4. Design and force `actor_work_quantum` only after the safety gate.
5. Design and force `buffer_copy_coalescing` only after ownership tests.
6. Review conservative-only `adaptive_backpressure` application-visible
   behavior.

No large adaptive dataset transform or ML analysis begins before these
architecture foundations are complete. No active behavior is authorized.

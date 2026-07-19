# Same-Connection Egress Design

Status: implementation prerequisite

This design addresses the one-connection, many-stream ceiling identified by
the retained July 2026 actor traces. It does not authorize another sender
queue, send wrapper, UDP segmentation variant, or packet-ordering shortcut.

## Evidence And Objective

The exact one-MiB fixed-response `1 x 16` diagnostic attributed approximately
27.36 ms of serialized actor service to each completed response. Hosted
datagram callbacks consumed 13.89 ms per response and 93.8 percent of effect
time. The actor emitted about 884 datagrams per response.

The objective is to overlap ordered socket emission with connection actor work
without accounting a packet as sent before the socket has accepted it. The
design must preserve congestion control, pacing, anti-amplification, packet
order, loss recovery, PTO, ECN, idle timeout, cancellation, disposal, FIN
recovery, and pooled-buffer ownership.

## Required State Machine

Each hosted datagram that participates in recovery moves through these states:

1. `prepared`: packet number and protected bytes exist, but no send budget is
   reserved.
2. `reserved`: congestion and anti-amplification budgets cover the datagram;
   the packet is not visible to ACK or loss processing.
3. `emitting`: one ordered connection-local emitter owns the protected buffer.
4. `emitted`: the socket accepted the complete datagram and recorded the actual
   emission timestamp.
5. `committed`: the actor moved the packet into sent-packet, recovery, ECN, and
   idle-timeout state using the actual emission timestamp.

Any failure before `emitted` releases the emission reservation and protected
buffer exactly once. Non-retransmittable packets then move to `released` and
are never exposed as sent. Retransmittable packets instead move to
`local_send_failed`: their plaintext or rebuild metadata is handed back to the
actor's existing retransmission path before the protected buffer is released.
They must not disappear merely because the socket rejected the first emission.

The first implementation slice must execute `emitting`, `emitted`, and
`committed` synchronously on the actor. It is an architecture and correctness
change only. A worker is not permitted until the synchronous reservation and
commit path passes the full correctness gate.

## Reservation Rules

- Reserved congestion bytes count against the sender's available window and
  pacing budget so preparing multiple datagrams cannot oversubscribe the path.
- Committing a reservation converts reserved bytes to in-flight bytes without
  charging the congestion window twice.
- Releasing a reservation restores all reserved budgets exactly once.
- Anti-amplification remains conservative: reservation may consume its budget
  before emission, but failed emission must restore it or close the path if the
  existing state model cannot restore it safely.
- Packet numbers are never reused after preparation, including failed local
  emission.
- ACK-only packets that do not retain sent-packet state still acquire an
  emission record so ECN, metrics, and ownership follow the same lifetime.

## Recovery And ACK Ordering

- `RecordPacketSent`, recovery deadlines, ECN sent counters, and idle-timeout
  sent activity use the actual emission timestamp and run only at commit.
- Pending reservations are not eligible for ACK removal, loss declaration,
  retransmission, or PTO calculation.
- A future emitter publishes an atomic `emitted` status and timestamp before it
  posts the actor completion item.
- The actor drains completed emissions before processing a packet-received
  item. ACK processing must also commit an atomically emitted token inline if
  its completion item has not yet been observed.
- An ACK for a genuinely un-emitted reservation retains the existing unknown
  packet behavior; it must not fabricate a send, free the reservation, or
  expose protected bytes.
- Completion processing is idempotent by connection-local emission sequence.
- A short send or transient socket error is not a peer-observable packet loss.
  It releases reserved congestion and anti-amplification budget, does not update
  ECN or RTT state, and schedules retransmittable plaintext through the actor.
  This preserves dropped-FIN recovery without pretending the packet entered the
  network. If the existing retransmission plan cannot be constructed, the
  connection fails closed rather than silently losing stream data.

## Emitter Rules

- Emission order is the actor's existing effect order. Packet numbers, paths,
  and ECN markings are not reordered.
- The eventual queue is connection-local and bounded to one pending datagram
  for the first performance candidate.
- The producer never drops a prepared datagram. When the bound is reached it
  performs the same coupled emission and commit synchronously.
- Socket success means the full datagram length was accepted. Short sends and
  exceptions follow the `local_send_failed` or `released` path according to
  whether the packet carries retransmittable state.
- The emitter owns each detached protected buffer until the socket operation
  completes. Sent-packet retransmission state retains its existing plaintext or
  rebuildable metadata independently.
- Shutdown stops admission, drains or fails every reservation, returns every
  owner, and prevents late completion from mutating a disposed runtime.

## Implementation Slices

### Slice A: synchronous reservation and commit

Extract the current application-packet accounting into prepare/reserve and
commit operations. Keep socket emission synchronous. The resulting runtime
must be behaviorally equivalent apart from the emission timestamp moving to
the actual socket boundary.

Required focused proof:

- congestion reservation cannot oversubscribe the window;
- commit does not double-charge bytes in flight;
- failed emission releases reservation and protected-buffer ownership once;
- failed retransmittable emission schedules plaintext or rebuild metadata once;
- ACK cannot remove an un-emitted reservation;
- emitted ACK-eliciting packets start recovery and idle-timeout state;
- ACK-only, probe, retransmission, FIN, and path-validation sends preserve
  their existing accounting;
- dropped and silently dropped FIN recovery tests pass repeatedly;
- cancellation, connection disposal, shard failure, and observer exceptions
  leave no reservation or owner behind.

### Slice B: one-pending-datagram emitter

Add a disabled connection-local emitter for established 1-RTT retransmittable
application datagrams only. It owns at most one pending datagram and posts the
send result to the same shard. All other sends retain the synchronous path.
First prove deterministic order, completion races, synchronous full-bound
fallback, shutdown, and failure recovery. Do not enable it in normal hosts
until those tests pass.

### Slice C: local promotion gate

Run matched frozen A/B evidence, preferably A/B/B/A, with exact payload,
content-length, EOF, and protocol validation:

- HTTP/3 fixed one MiB at `1 x 1`, `1 x 4`, and `1 x 16`;
- public transport download one MiB at `1 x 16`;
- one upload or duplex guardrail;
- focused concurrency and recovery tests;
- the full regression suite.

Promote only if `1 x 16` improves at least 10 percent or materially reduces
tail latency/allocation, `1 x 1` and `1 x 4` remain within approximately five
percent, and no protocol or lifetime invariant weakens. ProtocolLab remains
blocked until this local gate passes.

## Rejected Shortcuts

Do not substitute any of these for the state machine above:

- accounting a packet as sent before queued socket emission;
- another per-shard sender queue;
- `SendToAsync` submission without completion-coupled recovery;
- copied, scatter/gather, or dual-mode UDP segmentation;
- socket wrapper or ECN microvariants;
- packet, stream, or work-item reordering;
- ACK-ledger microvariants;
- a stream-action lock split or whole-request locked drain.

# Sender / Recovery Engine Decision Brief

This document is a decision brief, not a canonical architecture artifact. It summarizes the current repository evidence and the open design questions behind the sender and recovery wall.

## What This Seam Is

The sender / recovery engine is the transport-owned runtime that decides:

- what packets to send
- which frames or frame effects are outstanding
- which packet number space a transmission belongs to
- when loss is declared
- when PTO is armed, backed off, reset, and fired
- what is retransmitted, suppressed, updated, or discarded after loss or acknowledgment
- how congestion control, flow control, stream state, path validation, and key discard affect transmission behavior

The repo already has substantial helper and bounded runtime coverage in this area. What it does not yet have is a general sender/recovery engine that owns every retransmittable frame effect across flow control, stream state, connection-ID lifecycle, PMTU, and broader reliability behavior.

## Why This Is A Wall

The remaining work is not blocked by missing formulas. It is blocked by missing ownership of live transmission state outside the already-traced RFC 9002 Section 6 loss-detection lanes.

Today the repo can answer questions like:

- "What is the recommended PTO formula?"
- "How does ACK generation work for a packet number space?"
- "How do congestion and persistent congestion math work?"
- "How do I parse or format `MAX_DATA`, `STOP_SENDING`, `PATH_CHALLENGE`, or `NEW_CONNECTION_ID`?"

What it cannot answer yet is:

- "This packet was lost; which frame effects must be retransmitted, and which are now obsolete?"
- "PTO fired in Handshake space; what exact probe datagrams should be sent?"
- "A `MAX_STREAM_DATA` frame was lost after a newer one was sent; should the older one be retransmitted?"
- "A stream has been reset; which queued stream data must now be suppressed?"

That missing ownership is the actual wall.

## Requirement Scope Tied To This Seam

| Chunk | What the requirements are asking for | Current status |
| --- | --- | --- |
| `9000-19-retransmission-and-frame-reliability` | Retransmit reliability-sensitive frames until acknowledged or superseded, suppress obsolete retransmissions, handle whole-packet loss, and tie frame behavior to stream, path, and connection-ID lifecycle. | Only `REQ-QUIC-RFC9000-S13P3-0010` and `REQ-QUIC-RFC9000-S13P3-0027` are closed. The other 25 clauses are partial and 12 are blocked. |
| `9002-03-loss-detection` | Maintain per-space loss state, arm and rearm PTO, send probes, apply backoff rules, handle Retry and key discard, and compose PTO probe packets correctly. | Closed for the bounded repo-owned Section 6 loss-detection surfaces. Focused requirement-home execution now covers all 55 scoped requirements; broader sender/recovery work remains in adjacent chunks. |
| `9000-03-flow-control` follow-ons | Reconcile broader adaptive credit policy and generalized sender/recovery orchestration with reliability and loss. | The required runtime publication floor is closed; broader sender-owned reliability and adaptive credit policy remain outside that closed chunk. |
| `9000-02-stream-state` send/abort remainder | Own send-path transitions, retransmission behavior, ACK tracking, and `STOP_SENDING` / `RESET_STREAM` coordination. | Helper state exists, but live send-path orchestration is absent. |
| `9002-05` and `9002-06` appendix remainders | Appendix restatements of sender, timer, PMTU, and key-discard behavior. | Already split because the runtime layer does not exist yet. |

## What The Requirements Are Actually Asking Us To Do

### Reliability And Retransmission

The RFC 9000 reliability requirements are asking for an engine that can:

- remember what semantic effects were sent in each packet
- decide whether those effects are retransmittable, suppressible, or replaceable
- keep retransmitting required control information until acknowledged
- stop retransmitting when a newer frame or stream state supersedes the older one
- understand the difference between packet loss and logical data loss

### Loss Detection And PTO

The RFC 9002 loss-detection requirements are asking for an engine that can:

- maintain sent-packet state by packet number space
- arm and rearm loss and PTO timers
- restart PTO on send, ACK, and key discard events
- keep PTO expiration from falsely implying loss
- choose PTO probes based on packet number space, handshake confirmation, and address validation state
- send probe content that is still ack-eliciting and semantically correct

### Flow Control And Stream Send State

The remaining flow-control and stream-state requirements are asking for an engine that can:

- coordinate send credits with actual packet transmission
- emit blocked frames when the sender is limited
- retransmit or suppress control frames based on newer local state
- stop sending stream data when reset or final-size rules make further sends invalid

## Current Repository Evidence

The repo already has a significant helper layer:

- `src/Incursa.Quic/QuicRecoveryTiming.cs`
  - Loss-delay math, PTO formulas, timer selection, and PTO backoff/reset helpers.
- `src/Incursa.Quic/QuicRttEstimator.cs`
  - RTT sample processing and smoothing.
- `src/Incursa.Quic/QuicCongestionControlState.cs`
  - Congestion window, bytes in flight, ECN processing, pacing helpers, and persistent-congestion logic.
- `src/Incursa.Quic/QuicAckGenerationState.cs`
  - ACK range tracking, ACK generation, and delayed-ACK scheduling hints.
- `src/Incursa.Quic/QuicCongestionControlState.cs` also contains `QuicSenderFlowController`
  - A minimal facade that combines sent-packet tracking, congestion control, and ACK-generation state.
- `src/Incursa.Quic/QuicConnectionStreamState.cs`
  - Connection- and stream-level credit bookkeeping, final-size checks, and unique-byte accounting.
- `src/Incursa.Quic/QuicPathValidation.cs`
  - `PATH_CHALLENGE` helpers and path-validation measurements.
- `src/Incursa.Quic/QuicFrameCodec.cs` and the frame-specific types
  - Codecs for `ACK`, `STREAM`, `RESET_STREAM`, `STOP_SENDING`, `MAX_*`, `*_BLOCKED`, `PATH_CHALLENGE`, `PATH_RESPONSE`, `NEW_CONNECTION_ID`, `RETIRE_CONNECTION_ID`, `NEW_TOKEN`, `PING`, and `PADDING`.

The requirement closeouts and appendix reviews already state the limits of that evidence:

- `specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.closeout.md`
- `specs/generated/quic/chunks/9002-03-loss-detection.closeout.md`
- `specs/generated/quic/chunks/9000-03-flow-control.closeout.md`
- `specs/generated/quic/chunks/9000-02-stream-state.closeout.md`
- `specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.review.md`
- `specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.review.md`
- `specs/requirements/quic/REQUIREMENT-GAPS.md`

## Important Nuance: There Is Already A Small Facade

The wall is not "there is no sender type at all".

`QuicSenderFlowController` already exists and does useful work:

- keeps a sent-packet dictionary by packet number space
- records sent packets
- processes ACK frames against tracked packet numbers
- registers loss against tracked packet numbers
- exposes ACK scheduling and ACK building through `QuicAckGenerationState`
- delegates congestion changes into `QuicCongestionControlState`

That is good evidence. It is also not enough.

It still does not generally own:

- packet assembly
- retransmission planning
- PTO alarm ownership
- PTO probe composition
- semantic retransmission suppression
- connection-ID lifecycle effects
- stream send queue effects
- key-discard cleanup outside the closed RFC 9002 Section 6 loss-detection scope

So the real decision is whether to evolve this facade into the real engine or treat it as a low-level helper under a new runtime layer.

## What Is Missing

The missing pieces are runtime semantics, not isolated helpers.

The repo does not yet have a general-purpose sender/recovery layer with:

- a packet planner that decides what frames go into a packet
- a sent-packet record that stores semantic frame effects, not just bytes and timestamps
- a retransmission queue or retransmission planner
- a PTO owner for all sender/reliability surfaces beyond the closed Section 6 loss-detection slice
- a per-space loss state owner for frame-reliability and stream/flow-control recovery beyond the closed Section 6 loss-detection slice
- frame-suppression logic for obsolete control frames
- stream send queues tied to stream lifecycle
- a connection-ID manager that can reason about retransmission and retirement
- PMTU and wire-overhead accounting for bytes in flight
- key-discard cleanup for deferred appendix and adjacent reliability surfaces not already covered by the Section 6 closeout

## Why This Is Architectural Instead Of Just More Code

Every blocked requirement here needs a policy answer, not just storage.

Examples:

- `MAX_DATA` retransmission is not just "send again on loss". A newer `MAX_DATA` may supersede the older one.
- `PATH_RESPONSE` is not a normal reliable frame. It is a one-shot response to received challenge data.
- `STOP_SENDING` and `RESET_STREAM` interact with stream lifecycle. Retransmission policy depends on whether the stream is still live and whether newer state already made the old frame obsolete.
- PTO probes can contain new data, old data, `PING`, or content from another packet number space. That needs one policy owner.

Without an explicit runtime, the same semantic question will be answered differently in each feature area.

## Concrete Open Decisions

### 1. Do We Evolve `QuicSenderFlowController` Or Build Around It?

Option A: evolve `QuicSenderFlowController` into the transport's sender/recovery engine.

- Pros:
  - least churn
  - there is already public API shape and tests around it
  - natural place to add sent-packet metadata and PTO ownership
- Cons:
  - current name suggests a narrower responsibility than it will eventually carry

Option B: keep `QuicSenderFlowController` as a math-and-ledger helper and add a higher-level `QuicSendEngine` or `QuicRecoveryRuntime`.

- Pros:
  - cleaner separation between "stateful math helper" and "real transport runtime"
  - clearer surface for packet planner vs recovery manager
- Cons:
  - more wrapper code and duplicate transitions unless the boundaries are clean

Least risky direction for the current repo shape: evolve the existing facade, even if the type is later renamed.

### 2. Should Sent State Be Packet-Centric Or Frame-Centric?

Option A: packet-centric records that include a list of frame effects.

- Pros:
  - lines up with loss detection, ACK processing, and bytes-in-flight accounting
  - easiest way to implement "packet lost, then recover its retransmittable effects"
- Cons:
  - requires explicit modeling of effect types

Option B: frame-centric queues with packet references.

- Pros:
  - may look simpler for retransmission
- Cons:
  - makes bytes-in-flight and loss accounting more indirect
  - harder to reason about per-packet events

Least risky direction now: packet-centric records with typed frame effects.

### 3. Who Owns Recovery Timers?

Option A: sender/recovery engine owns the logical timers and exposes "next due time" to the outer runtime.

- Pros:
  - keeps recovery policy coherent
  - easiest way to implement PTO and loss-timer interactions
- Cons:
  - outer connection runtime still needs to schedule real clock events

Option B: connection runtime owns all timers and repeatedly asks helpers what to do.

- Pros:
  - fewer timer owners
- Cons:
  - recovery policy gets smeared across components

Least risky direction now: sender/recovery owns logical timer state, connection runtime owns the actual scheduling mechanism.

### 4. How Should Retransmission Suppression Work?

This needs an explicit rule set, not ad hoc conditionals.

At minimum the engine needs to distinguish:

- retransmit until acknowledged
- retransmit until superseded by a newer value
- do not retransmit after stream reset or final-state transition
- one-shot response only
- probe-only content

If this distinction is not modeled explicitly, the engine will either retransmit too much or suppress too aggressively.

### 5. How Much Stream Integration Is Required Up Front?

Questions that need a decision:

- Does the sender engine pull bytes from live stream objects, or does it consume already-decided frame requests?
- Does stream state own retransmittable data ranges, or does the sender engine own them once framed?
- Where do `STOP_SENDING` and `RESET_STREAM` suppress queued stream data?

This choice determines whether stream send-path work can proceed in parallel with recovery or must wait for it.

## Recommended Minimal Shape

The smallest architecture that appears sufficient is:

- one sender/recovery runtime rooted in the existing `QuicSenderFlowController` surface
- per-space sent-packet ledgers
- one typed `SentPacketRecord` that includes packet size, path, ack-eliciting status, bytes-in-flight status, and a list of frame effects
- one PTO state record that owns `ptoCount`, selected packet number space, and due time
- one retransmission-planning step that turns lost packet effects into new outbound work
- one suppression model for superseded frames

The runtime should be able to process inputs such as:

- packet sent
- ACK received
- loss declared
- PTO expired
- stream state changed
- path validated or invalidated
- keys discarded

And produce effects such as:

- retransmit these frame effects
- schedule PTO at time T
- declare these packets lost
- remove these packets from bytes in flight
- emit `PING` or probe packets
- suppress obsolete `MAX_*` or blocked frames

## What This Decision Unlocks

Picking the sender/recovery shape unlocks:

- the remaining 37 open clauses in `9000-19-retransmission-and-frame-reliability`
- the already-closed `9002-03-loss-detection` runtime proof as a baseline for adjacent reliability work
- the broader adaptive credit policy and generalized sender/recovery follow-ons outside the closed `9000-03-flow-control` publication floor
- the send-path and abort-coordination remainder in `9000-02-stream-state`
- the deferred appendix work in `9002-05` and `9002-06`

It also provides the place where key discard from the TLS bridge can clean up recovery state correctly.

## Questions For Decision-Making

If you want to guide this seam directly, these are the questions worth answering:

1. Do we evolve `QuicSenderFlowController` into the real runtime, or wrap it with a higher-level send engine?
2. Do we model sent state as packet records with frame effects, or as frame queues with packet references?
3. Does the sender/recovery engine own logical timer state, or does the connection runtime own all timer logic?
4. Where do retransmission-suppression rules live for superseded control frames?
5. How tightly should stream send queues be coupled to the sender engine in the first slice?

## Source Artifacts Consulted

- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.closeout.md`
- `specs/generated/quic/chunks/9002-03-loss-detection.closeout.md`
- `specs/generated/quic/chunks/9000-03-flow-control.closeout.md`
- `specs/generated/quic/chunks/9000-02-stream-state.closeout.md`
- `specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.review.md`
- `specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.review.md`
- `src/Incursa.Quic/QuicRecoveryTiming.cs`
- `src/Incursa.Quic/QuicRttEstimator.cs`
- `src/Incursa.Quic/QuicCongestionControlState.cs`
- `src/Incursa.Quic/QuicAckGenerationState.cs`
- `src/Incursa.Quic/QuicConnectionStreamState.cs`
- `src/Incursa.Quic/QuicPathValidation.cs`
- `src/Incursa.Quic/QuicFrameCodec.cs`

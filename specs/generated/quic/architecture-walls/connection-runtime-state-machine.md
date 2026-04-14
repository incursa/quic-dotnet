# Connection Runtime State Machine Decision Brief

This document is a decision brief, not a canonical architecture artifact. It summarizes the current repository evidence and the open design questions behind the connection-runtime wall.

## What This Seam Is

The connection runtime state machine is the connection-owned orchestrator that decides:

- which path is active
- whether the peer address is validated
- whether the connection is open, closing, draining, or discarded
- when idle timeout, migration, and stateless reset transitions occur
- how packet receive events, timer expirations, and local API actions translate into connection-level state transitions

The current repository has helper objects for isolated rules, but it does not have the runtime that owns the order of operations.

## Why This Is A Wall

Most of the remaining RFC 9000 work in this area is not blocked by missing math. It is blocked because the repo does not yet have one place that can answer questions like:

- "A packet arrived from a new address; is that a migration attempt, a rebinding, or an attack?"
- "A trailing token matches a stateless reset token; do we immediately tear down, enter draining, or ignore it?"
- "The idle timer expired while the connection was already closing; what can still be sent?"
- "A close signal arrived; which timer starts, which state changes, and what packets remain legal?"

Without a connection-owned runtime, the helpers cannot be composed into protocol behavior.

## Requirement Scope Tied To This Seam

| Chunk | What the requirements are asking for | Current status |
| --- | --- | --- |
| `9000-11-migration-core` | Gate migration on handshake confirmation, detect peer-address changes, validate new paths, manage anti-amplification on unvalidated addresses, choose silent close vs reset behavior, and reset per-path RTT/ECN/congestion state on migration. | Only the anti-amplification helper-backed slice is closed. The remaining 39 requirements are blocked by missing connection migration orchestration. |
| `9000-13-idle-and-close` | Compute the effective idle timeout, restart it on the right events, enter closing or draining at the right time, stop ordinary sending, and eventually discard connection state. | Idle-timeout bookkeeping and part of close/drain lifecycle are helper-backed. Immediate close and `CONNECTION_CLOSE` send/receive behavior remain blocked. |
| `9000-14-stateless-reset` | Detect potential stateless resets, match tokens, scope token memory correctly, decide whether to accept or emit a reset, and immediately transition the connection out of ordinary operation when a valid reset is detected. | Packet-layout and token helpers exist. Endpoint-lifecycle, receive/send triggering, token retirement, and reset-send limiting remain blocked. |
| Adjacent `9000-02-stream-state` work | Own live streams, gate inbound and outbound frames by stream state, and coordinate stream lifecycle with connection lifecycle. | Helper bookkeeping exists, but live stream objects and connection-owned stream orchestration are absent. |

## What The Requirements Are Actually Asking Us To Do

### Migration Core

The migration requirements are asking for a connection that can:

- know whether handshake confirmation has happened before allowing migration-sensitive behavior
- observe a packet from a different remote address and classify it
- remember the last validated address
- keep anti-amplification limits on unvalidated paths
- issue or respond to path validation traffic
- decide whether an apparent migration should be ignored, probed, silently closed, or answered with a stateless reset
- reset path-local transport state such as RTT, ECN validation, and congestion state when the active path changes

### Idle Timeout And Close

The idle and close requirements are asking for a connection that can:

- derive the effective idle timeout from local and peer transport parameters plus the PTO floor
- restart the idle timer only on the events RFC 9000 allows
- know whether ordinary sending is still legal
- enter closing or draining exactly once
- bind `CONNECTION_CLOSE` send and receive events to the lifecycle state
- eventually discard state after the close/drain lifetime completes

### Stateless Reset

The stateless reset requirements are asking for a connection or endpoint that can:

- decide whether an incoming datagram is even eligible for stateless reset processing
- remember which reset tokens are valid for which connection IDs and remote addresses
- distinguish a real token match from random trailing bytes
- tear down a live connection immediately when a valid reset is accepted
- retire or invalidate tokens as connection IDs are retired
- limit reset emission so the endpoint does not create loops or become an oracle

## Current Repository Evidence

The repo already has useful local helpers:

- `src/Incursa.Quic/QuicIdleTimeoutState.cs`
  - Computes the effective idle timeout and tracks restart/deadline bookkeeping.
- `src/Incursa.Quic/QuicConnectionLifecycleState.cs`
  - Models basic closing/draining flags and contains a minimal stateless-reset-to-draining bridge.
- `src/Incursa.Quic/QuicStatelessReset.cs`
  - Generates reset tokens, formats reset datagrams, extracts trailing tokens, and applies sizing and visible-prefix rules.
- `src/Incursa.Quic/QuicAntiAmplificationBudget.cs`
  - Tracks the pre-validation 3x amplification budget.
- `src/Incursa.Quic/QuicPathValidation.cs`
  - Generates `PATH_CHALLENGE` data, computes validation padding, and measures round-trip timing for validation probes.
- `src/Incursa.Quic/QuicConnectionStreamState.cs`
  - Provides connection-scoped stream, receive-limit, and send-limit bookkeeping, but not a live runtime.

The corresponding closeout artifacts explicitly confirm the shape of the remaining blockers:

- `specs/generated/quic/chunks/9000-11-migration-core.closeout.md`
- `specs/generated/quic/chunks/9000-13-idle-and-close.closeout.md`
- `specs/generated/quic/chunks/9000-14-stateless-reset.closeout.md`
- `specs/generated/quic/chunks/9000-02-stream-state.closeout.md`
- `specs/requirements/quic/REQUIREMENT-GAPS.md`

## What Is Missing

The missing piece is not one helper. It is the connection-owned control loop.

The repo does not yet have:

- an endpoint receive pipeline that classifies an incoming datagram and routes it into connection-owned state
- a connection phase model that covers at least establishing, active, closing, draining, and discarded
- a per-path state model with active path vs candidate path tracking
- a last-validated-address record
- a place to decide whether a new-address event is migration, rebinding, or noise
- a timer owner for idle timeout and close/drain deadlines
- a connection error surface that can map protocol events to close/drain transitions
- a connection-owned stream registry built on top of the helper stream bookkeeping

## Why This Is Architectural Instead Of Just More Code

Each blocked requirement needs an answer to both "what state do we store?" and "who is allowed to transition it?".

Examples:

- Idle timeout is not just a timer formula. Someone has to decide which events restart it and which do not.
- Stateless reset is not just token matching. Someone has to know whether a datagram belonged to a live connection, whether a close path is already underway, and what teardown semantics follow.
- Migration is not just path validation. Someone has to remember which path was valid before, which path is provisional now, and which transport state resets when the path becomes active.

If those answers are spread across helpers, the remaining requirements will stay ambiguous and hard to prove.

## Concrete Open Decisions

### 1. What Owns The Connection Runtime?

Option A: one central `QuicConnectionRuntime` or similarly named orchestrator with explicit sub-state records.

- Pros:
  - simplest ownership model
  - easiest place to hang timers, error routing, and lifecycle transitions
  - best fit for traceability because each requirement has a clear home
- Cons:
  - risks becoming a large class if not decomposed carefully

Option B: a thin connection shell that delegates to separate lifecycle, migration, and reset managers.

- Pros:
  - smaller focused components
  - clearer local unit boundaries
- Cons:
  - more interface design up front
  - harder to reason about transition ordering between components

Least risky direction for the current repo shape: Option A with small internal sub-state records, not three fully independent managers.

### 2. How Should Paths Be Modeled?

Option A: one active path plus one or more candidate paths.

- Pros:
  - matches the immediate RFC 9000 blocker set
  - keeps migration simpler
  - enough for validation, anti-amplification, and address-change handling
- Cons:
  - less future-proof if multipath-like concerns appear later

Option B: a generalized path table from the start.

- Pros:
  - more extensible
- Cons:
  - more state and policy than the current backlog needs

Least risky direction now: active path plus candidate-path records.

### 3. Where Should Stream Ownership Live?

Option A: the connection runtime owns a stream registry built on top of `QuicConnectionStreamState`.

- Pros:
  - lets connection lifecycle, migration, close, and stream state coordinate in one place
  - directly unlocks `S3P3`, `S3P4`, and `S3P5`
- Cons:
  - connection runtime grows in scope

Option B: a separate stream manager that the connection runtime calls into.

- Pros:
  - keeps stream details isolated
- Cons:
  - lifecycle and close coordination becomes cross-component immediately

This is not a pure stream-only decision. The close/drain behavior and reset handling both need a connection-owned answer.

### 4. How Should Close And Reset Interact?

Questions that need a concrete answer:

- Does a valid stateless reset immediately move to discarded state, or to draining with no ordinary sends?
- Does a received `CONNECTION_CLOSE` always enter draining, or can local policy still enter closing first?
- Where is the source of truth for "ordinary sending is no longer legal"?

The current `QuicConnectionLifecycleState` already models `CanSendPackets`; the unresolved part is when the runtime invokes those transitions.

## Recommended Minimal Shape

The smallest architecture that appears sufficient is:

- one connection-owned runtime object
- one explicit `ConnectionPhase` enum or equivalent phase record
- one active-path record and optional candidate-path records
- one connection-owned timer surface for idle and close/drain deadlines
- one stream registry layered over `QuicConnectionStreamState`
- one effect-returning receive/send transition API so tests can prove state changes without needing a full socket layer

In concrete terms, the runtime should be able to consume inputs such as:

- packet received on address X
- local close requested
- idle timer expired
- path challenge or response validated
- stateless reset token matched

And produce effects such as:

- send `PATH_CHALLENGE`
- enter closing
- enter draining
- discard state
- switch active path
- reject ordinary sending

## What This Decision Unlocks

Picking the connection runtime shape will immediately turn the following blocker clusters into normal implementation slices:

- `9000-11-migration-core`
- `9000-13-idle-and-close`
- `9000-14-stateless-reset`
- the live-stream and abort-coordination remainder of `9000-02-stream-state`

It also creates the place where the TLS bridge and sender/recovery engine can plug in:

- handshake confirmation can become a connection-owned event
- key discard can become a lifecycle event
- PTO and idle timers can stop competing for undefined ownership

## Questions For Decision-Making

If you want to guide this seam directly, these are the questions worth answering:

1. Do we want one `QuicConnectionRuntime` owner, or a thin connection shell with separate managers?
2. Do we model paths as active-plus-candidates, or as a generalized path table?
3. Should the connection own live stream objects now, or keep them behind a separate manager?
4. On a valid stateless reset, is the target state "draining" or "discarded immediately" in our runtime model?
5. Do we want state transitions to return explicit effects rather than performing I/O directly?

## Source Artifacts Consulted

- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `specs/generated/quic/chunks/9000-11-migration-core.closeout.md`
- `specs/generated/quic/chunks/9000-13-idle-and-close.closeout.md`
- `specs/generated/quic/chunks/9000-14-stateless-reset.closeout.md`
- `specs/generated/quic/chunks/9000-02-stream-state.closeout.md`
- `src/Incursa.Quic/QuicIdleTimeoutState.cs`
- `src/Incursa.Quic/QuicConnectionLifecycleState.cs`
- `src/Incursa.Quic/QuicStatelessReset.cs`
- `src/Incursa.Quic/QuicAntiAmplificationBudget.cs`
- `src/Incursa.Quic/QuicPathValidation.cs`
- `src/Incursa.Quic/QuicConnectionStreamState.cs`

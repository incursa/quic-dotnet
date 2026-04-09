# TLS Handshake And Key-Management Bridge Decision Brief

This document is a decision brief, not a canonical architecture artifact. It summarizes the current repository evidence and the open design questions behind the TLS handshake and key-management wall.

## What This Seam Is

The TLS handshake and key-management bridge is the contract between QUIC transport/runtime code and the TLS state that QUIC depends on.

This seam is responsible for turning TLS facts into transport events such as:

- transport parameters are available to send
- staged peer transport parameters are committed explicitly
- Initial, Handshake, 0-RTT, or 1-RTT keys are available
- peer handshake transcript completion is surfaced
- keys were updated
- old keys were discarded
- TLS produced an alert or other error condition

It is also responsible for preventing behavior RFC 9001 disallows, such as using TLS `KeyUpdate` messages as if QUIC key updates were driven by TLS itself.

## Why This Is A Wall

The repo already exposes pieces of TLS-adjacent wire shape, but it does not have the bridge that makes those pieces live protocol behavior.

Today the repo can answer questions like:

- "Did the short header preserve the Key Phase bit?"
- "Can we parse and format transport parameters correctly?"
- "Do we expose the TLS registry metadata for `quic_transport_parameters`?"

What it cannot answer yet is:

- "When does peer handshake transcript completion become true?"
- "Which 1-RTT key generation is current, and when do we rotate it?"
- "If the Key Phase bit changes, which keys do we attempt for decryption and when do we install the new generation?"
- "How do staged peer transport parameters reach the transport runtime, and when do they become committed?"
- "What happens if TLS emits a `KeyUpdate` message or a fatal alert?"

That missing contract is the TLS wall.

## Requirement Scope Tied To This Seam

| Chunk | What the requirements are asking for | Current status |
| --- | --- | --- |
| `9001-02-security-and-registry` | Key update after peer handshake transcript completion, Key Phase semantics, prohibition and handling of TLS `KeyUpdate` messages, handshake tamper detection, transport-parameter commitment, and TLS registry metadata. | Only 5 helper-backed requirements are closed. The remaining executable security clauses are blocked by missing handshake and key-management surfaces. |
| Cross-seam `9002-03-loss-detection` remainder | Reset PTO and discard recovery state when keys go away. | The timing helpers exist, but key-discard events do not yet exist as live runtime inputs. |
| Cross-seam `9002-06` appendix remainder | Connection-owned cleanup on key discard. | Still deferred because there is no bridge that exposes key lifecycle transitions to the sender/recovery runtime. |

## What The Requirements Are Actually Asking Us To Do

### Key Update

RFC 9001 Section 6 is asking for a transport that can:

- allow key update only after the bridge/runtime transcript-completion gate
- initialize Key Phase correctly
- toggle Key Phase for each update
- detect a peer key change from the Key Phase bit
- install updated packet-protection keys
- decrypt with the changed Key Phase when appropriate
- ensure both endpoints progress through the key update

### TLS Message And Error Handling

The same chunk is also asking for a transport that can:

- prohibit TLS `KeyUpdate` messages at the TLS message layer
- treat any received TLS `KeyUpdate` as a connection error
- fail closed when the handshake transcript is tampered with

### Transport Parameter Commitment

The transport-parameter security clauses are asking for:

- the ability to carry transport parameters in TLS messages
- the ability to treat peer transport parameters as committed handshake transcript material, not just as parsed bytes

## Current Repository Evidence

The repo already has helper-backed evidence for the parts that can be proven without a TLS handshake implementation:

- `src/Incursa.Quic/QuicShortHeaderPacket.cs`
  - Exposes the parsed Key Phase bit and preserves short-header control bits.
- `src/Incursa.Quic/QuicPacketParser.cs`
  - Parses short and long headers and preserves the opaque short-header remainder.
- `src/Incursa.Quic/QuicTransportParametersCodec.cs`
  - Parses and formats transport parameters and exposes the TLS registry metadata for extension 57.
- `src/Incursa.Quic/QuicTransportParameters.cs`
  - Structured view for parsed transport parameters.

The closeout for the chunk is explicit about the current ceiling:

- `REQ-QUIC-RFC9001-S6-0002`
- `REQ-QUIC-RFC9001-S8-0001`
- `REQ-QUIC-RFC9001-S10-0001`
- `REQ-QUIC-RFC9001-S10-0002`
- `REQ-QUIC-RFC9001-S10-0003`

Those are the only RFC 9001 requirements this repo shape can prove today.

The relevant artifact is:

- `specs/generated/quic/chunks/9001-02-security-and-registry.closeout.md`

## What Is Missing

The repo does not yet have:

- a TLS session abstraction or bridge contract
- a handshake-confirmation signal
- packet-protection key objects or generation state
- a key-update state machine
- a decryption pipeline that can try current vs next key generations
- a transport-visible TLS transcript or authentication result surface
- a TLS alert to QUIC error-mapping surface
- a live policy surface that can reject outbound or inbound TLS `KeyUpdate` messages
- key-discard events that the sender/recovery runtime can consume

## Why This Is Architectural Instead Of Just More Code

The blocked requirements are all about ownership and sequencing:

- Peer handshake transcript completion is not just a boolean. Someone has to define when it becomes true and which subsystems observe it.
- Key update is not just a bit toggle. Someone has to own current, next, and retired key generations and decide when they become valid for send and receive.
- Transport parameters are not just bytes. Someone has to tell the transport "these peer parameters are now committed".
- Key discard is not just cleanup. It must notify recovery so bytes in flight and timers are updated consistently.

If those decisions are not explicit, the transport, TLS adapter, and recovery logic will all grow their own partial interpretations.

## Concrete Open Decisions

### 1. What Is The Boundary Between QUIC And TLS?

Option A: define a narrow event-driven bridge, for example an `IQuicTlsBridge` or similarly named abstraction.

- Pros:
  - isolates the missing TLS implementation details
  - gives the transport a clean contract based on events and key handles
  - easiest to test at the transport layer
- Cons:
  - requires designing a deliberate event model up front

Option B: let transport code call directly into a concrete TLS implementation and pull state imperatively.

- Pros:
  - fewer initial types
- Cons:
  - tightly couples transport, TLS, and packet-protection behavior
  - makes testing and proof harder

Least risky direction for the current repo shape: Option A.

### 2. Who Owns Packet-Protection Keys?

Option A: the TLS bridge owns secret derivation and key generations, and exposes transport-safe handles or views.

- Pros:
  - keeps cryptographic lifecycle localized
  - clearer place to emit "keys available" and "keys discarded" events
- Cons:
  - transport still needs a local view of which generation is active

Option B: transport owns the full key-generation state after initial derivation.

- Pros:
  - fewer cross-component calls during packet processing
- Cons:
  - transport absorbs much more cryptographic lifecycle complexity

Least risky direction now: TLS bridge owns derivation and lifecycle events; transport owns selection of which valid generation to apply.

### 3. How Should Peer Handshake Transcript Completion Be Surfaced?

This needs one canonical signal.

Possible shapes:

- explicit event: `PeerHandshakeTranscriptCompleted`
- bridge property plus edge-triggered callback
- connection-runtime derived state from multiple lower-level TLS facts

The important requirement is that the rest of the transport stack has exactly one source of truth, because migration, application-data PTO, and key update all depend on it.

### 4. How Should Key Update Be Initiated And Observed?

Questions that need answers:

- Does the connection runtime request a key update explicitly?
- Does the TLS bridge expose "peer changed Key Phase" as an event, or does packet processing call back into the bridge to resolve it?
- How many key generations are simultaneously valid for receive?
- What is the transport-visible state for "old keys discarded"?

This is the core of the RFC 9001 Section 6 blocker set.

### 5. How Do Transport Parameters Become Authenticated?

The parser already exists. The missing question is the ownership model:

- does TLS hand the transport staged peer parameters and later a commit signal?
- does the transport supply raw bytes to TLS and later receive a commit result?
- where do parse failure, transcript failure, and policy failure become connection errors?

Without an answer here, `REQ-QUIC-RFC9001-S8-0002` cannot move.

## Recommended Minimal Shape

The smallest architecture that appears sufficient is:

- one narrow TLS bridge abstraction
- explicit transport-facing events for:
  - local transport parameters ready to send
  - peer transport parameters committed
  - Initial keys available
  - Handshake keys available
  - 1-RTT keys available
  - peer handshake transcript completed
  - key update installed
  - old keys discarded
  - TLS alert or fatal error
- one transport-visible key-lifecycle record that tracks which packet number spaces and 1-RTT generations are currently valid
- one explicit error-mapping path from TLS failures to QUIC connection close behavior

This does not require a full cryptographic implementation in the first slice. It requires the contract that the rest of the transport stack can be built against.

## What This Decision Unlocks

Picking the TLS bridge shape unlocks:

- the remaining executable blockers in `9001-02-security-and-registry`
- the key-discard related blockers in `9002-03-loss-detection`
- the deferred key-discard cleanup overlap in `9002-06`
- the peer-handshake-completion dependency in migration and application-data PTO behavior

It also gives the connection runtime and sender/recovery runtime a stable way to consume:

- peer handshake transcript completion
- key availability
- key discard
- committed peer transport parameters
- TLS-originated connection errors

## Questions For Decision-Making

If you want to guide this seam directly, these are the questions worth answering:

1. Do we want a narrow event-driven TLS bridge, or direct transport access to a concrete TLS implementation?
2. Does the TLS bridge own key derivation and generation lifecycle, or does transport own more of that state?
3. What exact event or state transition is the canonical source of truth for peer handshake transcript completion?
4. How should key updates be initiated, observed, and retired?
5. How do staged peer transport parameters become committed in the transport runtime?

## Source Artifacts Consulted

- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `specs/generated/quic/chunks/9001-02-security-and-registry.closeout.md`
- `specs/generated/quic/chunks/9002-03-loss-detection.closeout.md`
- `specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.review.md`
- `src/Incursa.Quic/QuicShortHeaderPacket.cs`
- `src/Incursa.Quic/QuicPacketParser.cs`
- `src/Incursa.Quic/QuicTransportParametersCodec.cs`
- `src/Incursa.Quic/QuicTransportParameters.cs`

# QUIC Future Architecture Analysis

Read-only planning artifact for `c:\src\incursa\quic-dotnet`.

## Scope And Guardrails

- This is an architecture analysis only.
- It does not change production behavior, requirements, or verification artifacts.
- It separates:
  - RFC-derived pressure from raw standards text.
  - Repo-owned architecture choices from standards obligations.
  - Current trace coverage from future work that is not yet canonical in SpecTrace.

## Source Posture

- The repo currently uses the trace-first workflow in [docs/requirements-workflow.md](/c:/src/incursa/quic-dotnet/docs/requirements-workflow.md).
- The current QUIC requirement front door in [specs/requirements/quic/README.md](/c:/src/incursa/quic-dotnet/specs/requirements/quic/README.md) only lists:
  - `SPEC-QUIC-INT.json`
  - `SPEC-QUIC-RFC8999.json`
  - `SPEC-QUIC-RFC9000.json`
  - `SPEC-QUIC-RFC9001.json`
  - `SPEC-QUIC-RFC9002.json`
  - `SPEC-QUIC-CRT.json`
  - `SPEC-QUIC-API.json`
- The gap ledger in [specs/requirements/quic/REQUIREMENT-GAPS.md](/c:/src/incursa/quic-dotnet/specs/requirements/quic/REQUIREMENT-GAPS.md) is still carrying active advisory and inventory gaps, so the repo is not at a “requirements complete” state for future protocol families.
- The raw RFC text files referenced by the task are present under [specs/rfcs](/c:/src/incursa/quic-dotnet/specs/rfcs).
- No direct contradiction surfaced between the generated SpecTrace artifacts and the raw RFC text in this slice. The main issue is missing coverage, not a standards conflict.

## RFC Inventory

| Raw RFC file(s) | Generated SpecTrace artifact(s) | Topic | Layer | Likely implementation horizon | Analysis note |
|---|---|---|---|---|---|
| `rfc8999.txt`, `rfc9000.txt`, `rfc9001.txt`, `rfc9002.txt` | `SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`, `SPEC-QUIC-CRT.json`, `SPEC-QUIC-INT.json`, `SPEC-QUIC-API.json` | QUIC invariants, v1 transport, TLS, recovery | core transport, handshake, recovery | current core | This is the committed base. Keep these seams stable because later standards work will lean on them rather than replace them. |
| `rfc9287.txt`, `rfc9368.txt`, `rfc9369.txt` | none yet | QUIC bit greasing, compatible version negotiation, QUIC v2 | transport core / versioning | near-term core hardening | These RFCs pressure version handling, packet classification, and ossification resistance. They should not be modeled as v1-only parser special cases. |
| `rfc9114.txt`, `rfc9204.txt`, `rfc9220.txt` | none yet | HTTP/3, QPACK, WebSockets over HTTP/3 | application adapter | near-term adapter | These are not transport-core responsibilities. They need clean adapter boundaries over QUIC streams and control streams. |
| `rfc9221.txt`, `rfc9297.txt`, `rfc9298.txt`, `rfc9484.txt` | none yet | QUIC DATAGRAM, HTTP Datagrams, Capsule Protocol, CONNECT-UDP, CONNECT-IP / MASQUE | datagram / proxy adapter | mid-term adapter | These standards need generic datagram plumbing from the core and framing/protocol adaptation above it. |
| `rfc9250.txt`, `rfc9461.txt`, `rfc9463.txt`, `rfc9464.txt` | none yet | DNS over QUIC and encrypted-DNS discovery material | DNS / application edge | later | These pressure application configuration and discovery surfaces more than the transport engine. Keep the core generic and the DNS binding external. |
| `rfc9308.txt`, `rfc9312.txt` | none yet | applicability guidance and manageability | cross-cutting ops / telemetry | ongoing | These standards should shape observability and deployment guidance, but not force expensive instrumentation into packet loops. |

## Architecture Pressure Map

### 1. QUIC Invariants, Versioning, And Ossification Resistance

RFC 8999, RFC 9287, RFC 9368, and RFC 9369 pressure the core to keep:

- Packet header classification and version negotiation as explicit policy boundaries.
- Version-specific behavior isolated from version-independent invariants.
- Greasing and compatible version negotiation represented as extension points, not ad hoc branches.
- Parser and handshake logic tolerant of future versions, not frozen to v1 assumptions.

This is the first place the core can paint itself into a corner. If version negotiation or greasing gets embedded into the lowest parser branches, later version families become expensive to add.

### 2. TLS, Packet Protection, And Recovery

RFC 9001 and RFC 9002 pressure the bridge between TLS state, packet protection, and recovery:

- TLS transcript and key schedule state must remain queryable without reflection.
- Recovery bookkeeping must stay separate from packet encoding/decoding.
- Key update lifecycle needs a clear boundary between the managed TLS bridge and the transport runtime.
- Congestion control and loss recovery should remain state machines with cheap internal queries, not public API surfaces.

This is already close to the right shape in the current repo, but the seam must stay narrow so later protocol families can reuse it without inheriting TLS details.

### 3. HTTP/3, QPACK, And WebSockets Over HTTP/3

RFC 9114, RFC 9204, and RFC 9220 pressure an adapter boundary above the transport:

- HTTP/3 control streams should not live inside the connection runtime.
- QPACK encoder/decoder state should not become a transport concern.
- Extended CONNECT and WebSockets over HTTP/3 should be framed as application protocol adapters that consume QUIC streams, not as new transport primitives.

If HTTP/3 or QPACK gets fused into `QuicConnectionRuntime`, the library will be harder to extend for other HTTP/3-based protocols and harder to test without reaching into internals.

### 4. QUIC DATAGRAM, HTTP Datagrams, Capsule Protocol, And MASQUE

RFC 9221, RFC 9297, RFC 9298, and RFC 9484 pressure a generic datagram boundary:

- The transport core should expose datagram capability and delivery as a generic primitive.
- HTTP Datagrams and Capsule Protocol should be adapter framing over that primitive.
- CONNECT-UDP and CONNECT-IP should consume datagrams and capsules without making the core aware of proxy semantics.

This family needs a low-allocation handoff path, because these are likely to live on the same packet-adjacent hot paths as transport logic.

### 5. DNS Over QUIC And Encrypted-DNS Discovery

RFC 9250, RFC 9461, RFC 9463, and RFC 9464 pressure the application and discovery edge:

- DNS query/response mapping should stay outside the transport runtime.
- Discovery material and resolver selection should be handled by configuration or higher-level adapters.
- The QUIC core should only provide the generic transport facilities needed by a DNS layer.

This is another place where the repo should resist growing “just one more protocol mode” inside the core.

### 6. Applicability And Manageability

RFC 9308 and RFC 9312 pressure the codebase to expose operational signals:

- Connection state, version, path, recovery, and supportability should be observable through typed seams.
- Manageability data should be cheap to sample and cheap to ignore.
- The observability path should not require per-packet heap allocation.

These RFCs strengthen the case for snapshots and semantic query methods. They do not justify a broad diagnostics subsystem in the transport hot path.

## Current Seams To Preserve

These are the seams that already support non-reflective testability and future-proofing:

- `QuicConnectionStreamSnapshot`, `QuicConnectionStreamSendStateSnapshot`, and `QuicByteRangeSetSnapshot` in:
  - [src/Incursa.Quic/QuicConnectionStreamSnapshot.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicConnectionStreamSnapshot.cs)
  - [src/Incursa.Quic/QuicConnectionStreamState.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicConnectionStreamState.cs)
  - [src/Incursa.Quic/QuicByteRangeSet.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicByteRangeSet.cs)
  - These are the right shape for immutable observation and restore in tests.
- `QuicHandshakeFlowCoordinator` in [src/Incursa.Quic/QuicHandshakeFlowCoordinator.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicHandshakeFlowCoordinator.cs)
  - It keeps connection-ID and packet-number choreography separate from the rest of the runtime.
- `QuicTlsTransportBridgeDriver` in [src/Incursa.Quic/QuicTlsTransportBridgeDriver.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTlsTransportBridgeDriver.cs)
  - It already exposes internal query and update seams for handshake and key-update state.
- `QuicTransportTlsBridgeState` in [src/Incursa.Quic/QuicTransportTlsBridgeState.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTransportTlsBridgeState.cs)
  - It keeps TLS material and verification state queryable without private reflection.
- `QuicConnectionRuntime` in [src/Incursa.Quic/QuicConnectionRuntime.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicConnectionRuntime.cs)
  - Existing internal seams like `HandshakeFlowCoordinator`, `RecoveryController`, `SendRuntime`, `DiagnosticsSink`, `DiagnosticsEnabled`, and bootstrap setters should remain the primary test/support boundary.
- `QuicListenerHost` in [src/Incursa.Quic/QuicListenerHost.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicListenerHost.cs)
  - Its pending-connection and handshake-datagram queries are the right harness-facing seam.
- `QuicPacketParser` in [src/Incursa.Quic/QuicPacketParser.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPacketParser.cs)
  - Parser helpers should stay query-oriented and side-effect free.
- `QuicCongestionControlState` in [src/Incursa.Quic/QuicCongestionControlState.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicCongestionControlState.cs)
  - It should remain a state machine with cheap internal queries, not a policy sink.
- The effect/event boundary in [src/Incursa.Quic/QuicConnectionRuntimeEventModels.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicConnectionRuntimeEventModels.cs)
  - This is fine at the edge, but it should not expand into deeper hot-path polymorphism.

## Seams Likely To Become Blockers

- `QuicConnectionRuntime` can become a catch-all if HTTP/3, MASQUE, DNS discovery, or manageability logic is pulled into it.
- `QuicListenerHost` already mixes version negotiation, Retry bootstrap, zero-RTT buffering, admission, and diagnostics. That is tolerable now, but it becomes fragile if protocol-family policy keeps accumulating there.
- `QuicTlsKeySchedule` in [src/Incursa.Quic/QuicTlsKeySchedule.cs](/c:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTlsKeySchedule.cs) centralizes transcript state, secrets, resumption, and key update behavior. That should stay TLS-only.
- `QuicPacketParser` and `QuicHandshakeFlowCoordinator` will need a version-policy layer above them if compatible version negotiation and QUIC v2 become real targets. Without that, v1 assumptions will leak into surrounding code.
- `QuicConnectionRuntimeEventModels` uses reference-typed boundary records. That is acceptable at the boundary, but it should not be cloned deeper into packet/frame loops.
- Any attempt to encode future protocol families as public APIs too early will freeze design choices before the corresponding requirement homes exist.

## Recommended Extension Points

Use these extension styles preferentially:

- `internal readonly record struct` snapshots for immutable observation and restore.
  - Good fit for stream state, packet-number state, versioning state, and other stable snapshots.
- `internal semantic query methods` such as `TryGet...`, `Has...`, `Can...`, and `Describe...`.
  - Prefer these over reflective access to fields and private methods.
- `internal test-support setup methods` for seeding a scenario.
  - Keep them explicit and narrow so tests do not depend on implementation details.
- `ReadOnlySpan<byte>` and `ReadOnlyMemory<byte>` for observation and handoff.
  - Avoid copying unless retention is required.
- Lightweight diagnostic sinks behind an optional boundary.
  - Manageability hooks should be cheap to disable and cheap to ignore.
- Adapter-facing datagram/capsule/proxy seams above transport.
  - Keep those protocols out of the transport engine itself.

Low-allocation constraints:

- Do not introduce per-packet heap allocation for observation or diagnostics.
- Do not introduce interface dispatch in packet parse/encode/recovery hot loops.
- Do not use object graphs when a struct snapshot or scalar query will do.
- Do not make test-only observation paths require a new runtime abstraction.

## Anti-Goals

- No new public APIs for future protocol families before canonical requirement homes exist.
- No HTTP/3, QPACK, WebSockets, MASQUE, DoQ, or discovery semantics inside `QuicConnectionRuntime`.
- No reflection-based tests or private-member probing.
- No per-packet heap allocation for diagnostics or manageability.
- No interface-dispatch plugin layer in packet and frame hot loops.
- No version-specific parser branches that erase the shape needed for compatible version negotiation or QUIC v2.
- No test-only “helper” that quietly becomes production policy.

## Refactor Backlog In Dependency Order

1. Freeze the current seam catalog and keep the no-private-reflection guard as the next testability slice.
2. Normalize versioning and greasing support around parser and handshake boundaries so compatible version negotiation and QUIC v2 can land without reworking the core.
3. Split transport-core responsibilities from application adapters:
   - HTTP/3
   - QPACK
   - WebSockets over HTTP/3
4. Add generic datagram and capsule/proxy extension points for:
   - QUIC DATAGRAM
   - HTTP Datagrams
   - Capsule Protocol
   - CONNECT-UDP
   - CONNECT-IP / MASQUE
5. Add DNS-over-QUIC and encrypted-DNS discovery surfaces after the transport boundary is stable.
6. Add manageability and observability surfaces last, then benchmark any hot-path changes before considering them settled.

## Proposed SpecTrace Requirement / Gap Updates

Do not make these changes in this slice. They are follow-up candidates:

- Add gap-ledger entries for the missing families:
  - HTTP/3
  - QPACK
  - WebSockets over HTTP/3
  - QUIC DATAGRAM
  - HTTP Datagrams / Capsule Protocol
  - CONNECT-UDP
  - CONNECT-IP / MASQUE
  - DNS over QUIC
  - encrypted-DNS discovery
  - greasing
  - compatible version negotiation
  - QUIC v2
  - applicability
  - manageability
- Decide whether those families need new canonical `SPEC-QUIC-*` homes or should be represented as requirement groups that extend existing transport, runtime, and interoperability specs.
- Keep gap ledger entries focused on missing trace coverage, not implementation commitments.
- If any family becomes canonical, add requirement, architecture, work-item, and verification artifacts before code.

## Exact Next Prompts

1. `Draft trace-only gap-ledger additions for the future QUIC families (HTTP/3, QPACK, WebSockets, DATAGRAM, MASQUE, DoQ, version negotiation/v2, manageability). Do not edit code or rewrite requirements.`
2. `Map QuicConnectionRuntime, QuicListenerHost, QuicHandshakeFlowCoordinator, QuicTlsTransportBridgeDriver, QuicTransportTlsBridgeState, QuicPacketParser, and QuicCongestionControlState into a stable boundary diagram with the minimum internal seams needed for testability.`
3. `List the exact internal snapshot/query/setup seams tests should use instead of private reflection, and classify each seam as permanent, adapter-facing, or test-only.`
4. `Rank the future RFC families into a dependency-ordered backlog with low-allocation constraints and no public API changes.`

## Sources Used

Repository files:

- [docs/requirements-workflow.md](/c:/src/incursa/quic-dotnet/docs/requirements-workflow.md)
- [specs/requirements/quic/REQUIREMENT-GAPS.md](/c:/src/incursa/quic-dotnet/specs/requirements/quic/REQUIREMENT-GAPS.md)
- [specs/requirements/quic/README.md](/c:/src/incursa/quic-dotnet/specs/requirements/quic/README.md)
- [specs/architecture/quic/README.md](/c:/src/incursa/quic-dotnet/specs/architecture/quic/README.md)
- [specs/rfcs](/c:/src/incursa/quic-dotnet/specs/rfcs)

RFC Editor references:

- https://www.rfc-editor.org/rfc/rfc8999.html
- https://www.rfc-editor.org/rfc/rfc9000.html
- https://www.rfc-editor.org/rfc/rfc9001.html
- https://www.rfc-editor.org/rfc/rfc9002.html
- https://www.rfc-editor.org/rfc/rfc9114.html
- https://www.rfc-editor.org/rfc/rfc9204.html
- https://www.rfc-editor.org/rfc/rfc9220.html
- https://www.rfc-editor.org/rfc/rfc9221.html
- https://www.rfc-editor.org/rfc/rfc9250.html
- https://www.rfc-editor.org/rfc/rfc9287.html
- https://www.rfc-editor.org/rfc/rfc9297.html
- https://www.rfc-editor.org/rfc/rfc9298.html
- https://www.rfc-editor.org/rfc/rfc9308.html
- https://www.rfc-editor.org/rfc/rfc9312.html
- https://www.rfc-editor.org/rfc/rfc9368.html
- https://www.rfc-editor.org/rfc/rfc9369.html
- https://www.rfc-editor.org/rfc/rfc9461.html
- https://www.rfc-editor.org/rfc/rfc9463.html
- https://www.rfc-editor.org/rfc/rfc9464.html
- https://www.rfc-editor.org/rfc/rfc9484.html


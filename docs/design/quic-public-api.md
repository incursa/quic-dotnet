# Incursa.Quic Public API Surface

This note is the maintainer-facing companion to the public surface slice defined by `SPEC-QUIC-API`, `ARC-QUIC-API-0001`, `WI-QUIC-API-0001`, and `VER-QUIC-API-0001`.

The intent is to keep the consumer contract small and stable while the existing helper-layer transport engine stays internal.

## Baseline Used

The baseline for this initial cut is the public/ref surface in Microsoft `System.Net.Quic`:

- `C:\src\dotnet\runtime\src\libraries\System.Net.Quic\ref\System.Net.Quic.cs`

That ref file is the strongest reference for the initial consumer shape. The current `src/Incursa.Quic/PublicAPI.Unshipped.txt` file is broader than the intended consumer surface and should be treated as analyzer staging, not as the final public contract.

## Proposed Public Surface

### Connection-First Slice

This pass only promotes the consumer-lifetime facade that is already backed by the existing runtime and stream-state machinery:

- `QuicConnection`
- `QuicStream`
- `QuicConnectionOptions`
- `QuicReceiveWindowSizes`
- `QuicAbortDirection`
- `QuicError`
- `QuicException`
- `QuicStreamType` with the direction-only `Bidirectional` and `Unidirectional` values

### Deferred To The Next Slice

The following remain intentionally out of scope for this pass:

- `QuicListener`
- `QuicListenerOptions`
- `QuicClientConnectionOptions`
- `QuicServerConnectionOptions`
- `QuicStreamCapacityChangedArgs`
- `QuicConnection.ConnectAsync(...)`
- `QuicListener.ListenAsync(...)`
- `QuicListener.AcceptConnectionAsync(...)`
- `QuicConnection.AcceptInboundStreamAsync(...)`
- `QuicConnection.OpenOutboundStreamAsync(...)`
- `QuicConnection.IsSupported`
- `QuicListener.IsSupported`

## Behavioral Evidence

The Microsoft library-focused tests below were the most informative behavioral references for the initial cut:

- `tests/FunctionalTests/QuicListenerTests.cs`
- `tests/FunctionalTests/QuicConnectionTests.cs`
- `tests/FunctionalTests/QuicStreamTests.cs`
- `tests/FunctionalTests/QuicStreamConnectedStreamConformanceTests.cs`
- `tests/FunctionalTests/MsQuicCipherSuitesPolicyTests.cs`
- `tests/FunctionalTests/MsQuicTests.cs`

They imply these public-behavior expectations:

- Listener setup is validation-heavy: `ApplicationProtocols` is required, the listener callback is a narrow server-options selector, and the callback sees a cancellation token that is canceled on timeout or listener disposal.
- Client connect requires a remote endpoint, client auth options, and initialized default close and stream error codes before the connect begins.
- Listener accept, blocked stream open, and close operations must honor cancellation while the operation is still pending.
- `QuicStream` is a consumer-facing `Stream` abstraction with direction-based `CanRead` and `CanWrite`, timeout support, EOF handling, graceful write completion, and terminal `ReadsClosed` / `WritesClosed` tasks.
- Stream abort, connection close, and dispose must map to the public `QuicError` surface and preserve the configured application error codes.
- `StreamCapacityCallback` is a capacity notification surface, not a general event pipeline, and the callback reports bidirectional and unidirectional increments.
- The public API should reuse the BCL TLS options objects directly, including cipher-suite policy and certificate callbacks.
- Idle timeout and repeated close behavior belong to the public terminal-state contract, not to internal runtime state.

## Spec Refinements

This pass narrows the first consumer slice to the connection/stream facade and defers the listener and TLS-auth contract:

- `REQ-QUIC-API-0001` keeps the helper/runtime/wire surface internal while the facade is promoted.
- `REQ-QUIC-API-0004` only promises the stream identity, lifetime, EOF, and read-side behavior that is backed by `QuicConnectionStreamState`.
- `REQ-QUIC-API-0005` covers the shared connection options and receive-window settings that are already backed by the runtime seam.
- `REQ-QUIC-API-0006` records the public close/error projection through `QuicError`, `QuicException`, and `QuicAbortDirection`.
- `REQ-QUIC-API-0002`, `REQ-QUIC-API-0005`, and `REQ-QUIC-API-0008` leave listener, connect, accept, stream-open, and full TLS option plumbing to the next slice.

## Public Member Shape

The first slice keeps the consumer contract intentionally narrow:

- `QuicConnection` is the connection-lifetime facade over the runtime seam.
- `QuicStream` is the stream-lifetime facade over the stream-state seam.
- `QuicConnectionOptions` is the shared bag for connection close/error defaults, timeouts, and receive-window knobs.
- `QuicReceiveWindowSizes` carries the configured receive-window values.
- `QuicException` carries the close/error classification.
- `QuicAbortDirection`, `QuicError`, and `QuicStreamType` are the public classification enums used by the facade.

The public types do not introduce new endpoint or TLS wrapper abstractions in this slice. `QuicClientConnectionOptions`, `QuicServerConnectionOptions`, `QuicListenerOptions`, and `QuicStreamCapacityChangedArgs` remain deferred until the next slice, when the listener and connect surface are promoted.

## Listener And Connection Split

The listener and connect entry points are intentionally deferred in this pass.

- The connection-first slice reuses `QuicConnectionRuntime` and `QuicConnectionStreamState` directly.
- Listener startup, listener acceptance, and client connect remain the next slice.
- The capacity callback surface remains deferred until the stream-capacity path exists end to end.

## Internal-Only Boundary

The following seam types stay internal and should not be part of the consumer contract:

- `QuicTlsTranscriptProgress`
- `QuicTlsKeySchedule`
- `QuicTransportTlsBridgeState`
- `QuicHandshakeFlowCoordinator`
- `QuicInitialPacketProtection`
- `QuicHandshakePacketProtection`
- `QuicTlsPacketProtectionMaterial`
- `QuicConnectionRuntime`
- `QuicConnectionRuntimeHost`
- `QuicConnectionRuntimeShard`
- `QuicConnectionSendRuntime`
- `QuicConnectionRuntimeDeadlineScheduler`
- `QuicConnectionStreamState`
- `QuicConnectionStreamRegistry`
- `QuicConnectionStreamStateOptions`
- `QuicConnectionStreamSnapshot`
- `QuicConnectionLifecycleState`
- `QuicIdleTimeoutState`
- `QuicStreamId`
- `QuicStreamFrame`
- `QuicStreamParser`
- `QuicTransportErrorCode`
- `QuicTransportParameters`
- `QuicTransportParametersCodec`
- `QuicVersionNegotiation`
- `QuicFrameCodec`
- `QuicConnectionCloseFrame`
- `QuicResetStreamFrame`
- `QuicStopSendingFrame`
- `QuicMaxDataFrame`
- `QuicMaxStreamDataFrame`
- `QuicMaxStreamsFrame`
- `QuicDataBlockedFrame`
- `QuicStreamDataBlockedFrame`
- `QuicStreamsBlockedFrame`

The remainder of the packet, frame, transport-parameter, recovery, congestion, and stream-identity helpers also remain internal unless a future requirement explicitly promotes one of them.

## Intentional Deviations

No intentional deviations from the Microsoft ref surface are required for this initial cut.

The repo-specific rule is that the richer internal transport engine stays hidden behind the consumer facade, and the public surface does not grow into a general middleware model.

## Trace Links

- Specification: `../../specs/requirements/quic/SPEC-QUIC-API.json`
- Architecture: `../../specs/architecture/quic/ARC-QUIC-API-0001.json`
- Work item: `../../specs/work-items/quic/WI-QUIC-API-0001.json`
- Verification: `../../specs/verification/quic/VER-QUIC-API-0001.json`

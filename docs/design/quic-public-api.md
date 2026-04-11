# Incursa.Quic Public API Surface

This note is the maintainer-facing companion to the public surface slice defined by `SPEC-QUIC-API`, `ARC-QUIC-API-0001`, `WI-QUIC-API-0001`, and `VER-QUIC-API-0001`.

The intent is to keep the consumer contract small and stable while the existing helper-layer transport engine stays internal.

## Baseline Used

The baseline for this initial cut is the public/ref surface in Microsoft `System.Net.Quic`:

- `C:\src\dotnet\runtime\src\libraries\System.Net.Quic\ref\System.Net.Quic.cs`

That ref file is the strongest reference for the initial consumer shape. The current `src/Incursa.Quic/PublicAPI.Unshipped.txt` file is broader than the intended consumer surface and should be treated as analyzer staging, not as the final public contract.

## Proposed Public Surface

### Connection, Listener, And Client-Entry Slice

This pass promotes the consumer-lifetime facade that is already backed by the existing runtime and stream-state machinery, plus the first server-side listener surface:

- `QuicConnection`
- `QuicStream`
- `QuicConnectionOptions`
- `QuicReceiveWindowSizes`
- `QuicAbortDirection`
- `QuicError`
- `QuicException`
- `QuicListener`
- `QuicListenerOptions`
- `QuicClientConnectionOptions`
- `QuicServerConnectionOptions`
- `QuicConnection.ConnectAsync(...)`
- `QuicStreamType` with the direction-only `Bidirectional` and `Unidirectional` values

### Deferred After This Slice

The following remain intentionally out of scope for this pass:

- `QuicStreamCapacityChangedArgs`
- `QuicConnection.AcceptInboundStreamAsync(...)`
- `QuicConnection.OpenOutboundStreamAsync(...)`
- `QuicConnection.IsSupported`
- `QuicListener.IsSupported`

## Behavioral Evidence

The Microsoft library-focused tests below were the most informative behavioral references for this slice:

- `tests/FunctionalTests/QuicListenerTests.cs`
- `tests/FunctionalTests/QuicConnectionTests.cs`
- `tests/FunctionalTests/QuicStreamTests.cs`
- `tests/FunctionalTests/QuicStreamConnectedStreamConformanceTests.cs`
- `tests/FunctionalTests/MsQuicCipherSuitesPolicyTests.cs`
- `tests/FunctionalTests/MsQuicTests.cs`

They imply these public-behavior expectations:

- Listener setup is validation-heavy: `ListenEndPoint`, `ApplicationProtocols`, and the narrow server callback are required, and the callback sees a cancellation token that is canceled on timeout or listener disposal.
- Listener accept, blocked stream open, and close operations must honor cancellation while the operation is still pending.
- `QuicStream` is a consumer-facing `Stream` abstraction with direction-based `CanRead` and `CanWrite`, timeout support, EOF handling, graceful write completion, and terminal `ReadsClosed` / `WritesClosed` tasks.
- Stream abort, connection close, and dispose must map to the public `QuicError` surface and preserve the configured application error codes.
- The public API should reuse the BCL TLS options objects directly where that slice needs them, including the listener endpoint and server authentication options.
- Idle timeout and repeated close behavior belong to the public terminal-state contract, not to internal runtime state.

## Spec Refinements

This pass promotes the connection/stream facade, the listener/server entry surface, and the first honest client-entry shell while keeping the remaining TLS and stream work narrow:

- `REQ-QUIC-API-0001` keeps the helper/runtime/wire surface internal while the facade is promoted.
- `REQ-QUIC-API-0002` covers the server listener and client connect entry surfaces and their honest pending/terminal behavior.
- `REQ-QUIC-API-0004` only promises the stream identity, lifetime, EOF, and read-side behavior that is backed by `QuicConnectionStreamState`.
- `REQ-QUIC-API-0005` covers the shared connection options, listener options, receive-window settings, and the narrow supported subset of `SslClientAuthenticationOptions`.
- `REQ-QUIC-API-0006` records the public close/error projection through `QuicError`, `QuicException`, and `QuicAbortDirection`.
- `REQ-QUIC-API-0008` covers the cancellation and terminal-state behavior for listener accept, pending client connect, stream open, and close.

## Public Member Shape

The first slice keeps the consumer contract intentionally narrow:

- `QuicConnection` is the connection-lifetime facade over the runtime seam and exposes the client connect entry point.
- `QuicStream` is the stream-lifetime facade over the stream-state seam.
- `QuicConnectionOptions` is the shared bag for connection close/error defaults, timeouts, and receive-window knobs.
- `QuicReceiveWindowSizes` carries the configured receive-window values.
- `QuicException` carries the close/error classification.
- `QuicAbortDirection`, `QuicError`, and `QuicStreamType` are the public classification enums used by the facade.

The public types do not introduce new endpoint or TLS wrapper abstractions in this slice. `QuicListener`, `QuicListenerOptions`, `QuicServerConnectionOptions`, and `QuicClientConnectionOptions` are now part of the approved facade, while `QuicStreamCapacityChangedArgs` remains deferred.

## Listener And Client Split

The listener entry points are now part of this slice.

- The connection/listener/client slice reuses `QuicConnectionRuntime`, `QuicConnectionStreamState`, `QuicListenerHost`, `QuicConnectionRuntimeEndpoint`, `QuicConnectionEndpointHost`, and `QuicClientConnectionHost` directly.
- Listener startup and listener acceptance are honest and backed by the internal listener host.
- Client connect now starts a real client host/runtime shell and completes on the supported positive loopback boundary through the existing host seams, with Initial/DCID bootstrap, inbound Initial handling, and listener-side datagram admission already in place.
- The supported `SslClientAuthenticationOptions` subset is intentionally narrow: non-empty ALPN, TLS 1.3 or the default protocol selection, no target host or SNI/hostname validation, no client certificates, no chain policy, and an explicit `RemoteCertificateValidationCallback` gate over the parsed peer leaf certificate. Unsupported settings are rejected deterministically instead of being ignored.
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
- `QuicListenerHost`
- `QuicConnectionRuntimeShard`
- `QuicConnectionSendRuntime`
- `QuicConnectionRuntimeEndpoint`
- `QuicConnectionEndpointHost`
- `QuicClientConnectionHost`
- `QuicClientConnectionOptionsValidator`
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

The repo-specific rule is that the richer internal transport engine stays hidden behind the consumer facade, the supported client TLS/auth subset is explicit and reject-first, and the public surface does not grow into a general middleware model.

## Trace Links

- Specification: `../../specs/requirements/quic/SPEC-QUIC-API.json`
- Architecture: `../../specs/architecture/quic/ARC-QUIC-API-0001.json`
- Work item: `../../specs/work-items/quic/WI-QUIC-API-0001.json`
- Verification: `../../specs/verification/quic/VER-QUIC-API-0001.json`

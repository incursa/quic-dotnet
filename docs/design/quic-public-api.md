# Incursa.Quic Public API Surface

This note is the maintainer-facing companion to the public surface slice defined by `SPEC-QUIC-API`, `ARC-QUIC-API-0001`, `WI-QUIC-API-0001`, and `VER-QUIC-API-0001`.

The intent is to keep the consumer contract small and stable while the existing helper-layer transport engine stays internal.

## Baseline Used

The baseline for this initial cut is the public/ref surface in Microsoft `System.Net.Quic`:

- `C:\src\dotnet\runtime\src\libraries\System.Net.Quic\ref\System.Net.Quic.cs`

That ref file is the strongest reference for the initial consumer shape. The current `src/Incursa.Quic/PublicAPI.Unshipped.txt` file is broader than the intended consumer surface and should be treated as analyzer staging, not as the final public contract.

## Proposed Public Surface

### Capability Probes And Entry Points

- `QuicConnection.IsSupported`
- `QuicListener.IsSupported`
- `QuicConnection.ConnectAsync(...)`
- `QuicListener.ListenAsync(...)`
- `QuicListener.AcceptConnectionAsync(...)`
- `QuicConnection.AcceptInboundStreamAsync(...)`
- `QuicConnection.OpenOutboundStreamAsync(...)`

### Main Object Model

- `QuicListener`
- `QuicConnection`
- `QuicStream`

### Configuration And Callback Types

- `QuicConnectionOptions`
- `QuicClientConnectionOptions`
- `QuicServerConnectionOptions`
- `QuicListenerOptions`
- `QuicReceiveWindowSizes`
- `QuicStreamCapacityChangedArgs`

### Close And Error Surface

- `QuicAbortDirection`
- `QuicError`
- `QuicException`

### Stream Typing

- `QuicStreamType` with the Microsoft-style `Bidirectional` and `Unidirectional` values

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

This pass tightened the canonical requirement set in three places:

- `REQ-QUIC-API-0005` now calls out the mandatory listener and client option inputs that the Microsoft tests prove are required.
- `REQ-QUIC-API-0006` now records invalid close-code validation, idempotent close behavior, and `DisposeAsync` as the consumer-facing cleanup path.
- `REQ-QUIC-API-0008` now captures the async cancellation and terminal-state rules for connect, listen, accept, open-stream, close, and the server callback token.

## Public Member Shape

The initial cut should keep the Microsoft-shaped consumer contract:

- `QuicConnection` is the connected session object.
- `QuicListener` is the server-side accept/listen object.
- `QuicStream` is a `Stream`-derived QUIC stream wrapper.
- `QuicConnectionOptions` is the shared base for per-connection settings.
- `QuicClientConnectionOptions` and `QuicServerConnectionOptions` split the client and server configuration paths.
- `QuicListenerOptions` owns listener configuration and the server-side connection-options callback.
- `QuicReceiveWindowSizes` carries the configured receive-window knobs.
- `QuicException` carries the close/error classification.

The public types should reuse `EndPoint`, `IPEndPoint`, `SslApplicationProtocol`, `SslClientAuthenticationOptions`, `SslServerAuthenticationOptions`, and `SslClientHelloInfo` directly rather than introduce new endpoint or TLS wrapper abstractions.

## Listener And Connection Split

- Client connection establishment goes through `QuicConnection.ConnectAsync(QuicClientConnectionOptions, CancellationToken)`.
- Server startup goes through `QuicListener.ListenAsync(QuicListenerOptions, CancellationToken)`.
- Incoming server connections are accepted through `QuicListener.AcceptConnectionAsync(CancellationToken)`.
- `QuicListenerOptions.ConnectionOptionsCallback` is the only server-side dynamic configuration hook in the public surface.
- `QuicConnectionOptions.StreamCapacityCallback` is a narrow capacity notification hook, not a middleware or interception pipeline.

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

The remainder of the packet, frame, transport-parameter, recovery, congestion, and stream-identity helpers also remain internal unless a future requirement explicitly promotes one of them.

## Intentional Deviations

No intentional deviations from the Microsoft ref surface are required for this initial cut.

The repo-specific rule is that the richer internal transport engine stays hidden behind the consumer facade, and the public surface does not grow into a general middleware model.

## Trace Links

- Specification: `../../specs/requirements/quic/SPEC-QUIC-API.json`
- Architecture: `../../specs/architecture/quic/ARC-QUIC-API-0001.json`
- Work item: `../../specs/work-items/quic/WI-QUIC-API-0001.json`
- Verification: `../../specs/verification/quic/VER-QUIC-API-0001.json`

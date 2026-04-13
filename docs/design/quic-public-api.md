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
- `QuicPeerCertificatePolicy`
- `QuicServerConnectionOptions`
- `QuicStreamCapacityChangedArgs`
- `QuicConnectionOptions.StreamCapacityCallback`
- `QuicConnection.IsSupported`
- `QuicListener.IsSupported`
- `QuicConnection.ConnectAsync(...)`
- `QuicConnection.AcceptInboundStreamAsync(...)`
- `QuicConnection.OpenOutboundStreamAsync(...)`
- `QuicStreamType` with the direction-only `Bidirectional` and `Unidirectional` values

### Deferred After This Slice

The following remain intentionally out of scope for this pass:

- combined `Abort(Both, ...)`
- `0-RTT`
- key update
- interop-runner enablement

## Behavioral Evidence

The Microsoft library-focused tests below were the most informative behavioral references for this slice:

- `tests/FunctionalTests/QuicListenerTests.cs`
- `tests/FunctionalTests/QuicConnectionTests.cs`
- `tests/FunctionalTests/QuicStreamTests.cs`
- `tests/FunctionalTests/QuicStreamConnectedStreamConformanceTests.cs`
- `tests/FunctionalTests/MsQuicCipherSuitesPolicyTests.cs`
- `tests/FunctionalTests/MsQuicTests.cs`
- `tests/FunctionalTests/MsQuicPlatformDetectionTests.cs`

They imply these public-behavior expectations:

- Listener setup is validation-heavy: `ListenEndPoint`, `ApplicationProtocols`, and the narrow server callback are required, and the callback sees a cancellation token that is canceled on timeout or listener disposal.
- Listener accept, blocked stream open, and close operations must honor cancellation while the operation is still pending.
- `QuicStream` is a consumer-facing `Stream` abstraction, and this repo now supports a narrow read-side plus write/completion subset honestly on send-capable streams, plus a narrow `RESET_STREAM` / `STOP_SENDING`-backed `Abort(QuicAbortDirection.Read, ...)` / `Abort(QuicAbortDirection.Write, ...)` pair and matching `ReadsClosed` / `WritesClosed` outcomes on that same path; `Flush` stays a narrow no-op, and combined `Abort(Both, ...)` plus broader abort-heavy behavior remains out of scope.
- Stream entry points are only honest on an active connection that already has the minimal 1-RTT application-data lane; the supported loopback path opens and accepts a real QUIC stream facade and can now publish bytes, EOF, and the supported abort pair without exposing the broader abort-heavy contract.
- The stream-capacity callback is only honest for the initial peer stream-capacity increment committed from peer transport parameters on the supported loopback path, later real peer `MAX_STREAMS` growth on the supported active loopback path, and the narrow close-driven release subset where a peer-initiated stream reaches the supported locally closed state and the runtime emits one real `MAX_STREAMS` increment on that same path.
- `IsSupported` is only honest as a narrow runtime capability marker, not as a full native-QUIC or feature-completeness flag.
- Stream abort, connection close, and dispose must map to the public `QuicError` surface and preserve the configured application error codes.
- The public API should reuse the BCL TLS options objects directly where that slice needs them, including the listener endpoint and server authentication options.
- Idle timeout and repeated close behavior belong to the public terminal-state contract, not to internal runtime state.

## Spec Refinements

This pass promotes the connection/stream facade, the listener/server entry surface, and the first honest client-entry shell while keeping the remaining TLS and stream work narrow:

- `REQ-QUIC-API-0001` keeps the helper/runtime/wire surface internal while the facade is promoted.
- `REQ-QUIC-API-0002` covers the server listener and client connect entry surfaces and their honest pending/terminal behavior.
- `REQ-QUIC-API-0003` now covers the connected-session facade plus the supported stream-entry boundary on the established loopback path.
- `REQ-QUIC-API-0004` only promises the stream identity, lifetime, EOF, stream-entry, and the narrow read-side, write-side completion, and abort members that are backed by `QuicConnectionStreamState`.
- `REQ-QUIC-API-0005` covers the shared connection options, listener options, receive-window settings, the supported stream-capacity callback subset, and the narrow supported subset of `SslClientAuthenticationOptions`.
- `REQ-QUIC-API-0006` records the public close/error projection through `QuicError`, `QuicException`, and the currently supported `QuicAbortDirection.Read` / `QuicAbortDirection.Write` subset.
- `REQ-QUIC-API-0008` covers the cancellation and terminal-state behavior for listener accept, pending client connect, stream open, stream accept, supported write, close, and stream-capacity callback dispatch honesty.
- `REQ-QUIC-API-0009` covers the supported stream-capacity callback deltas on the supported loopback and active-loopback paths, including real peer stream-close-driven release on the supported active-loopback path.
- `REQ-QUIC-API-0010` covers the narrow runtime-backed stream write, completion, and write-abort lane on send-capable streams.
- `REQ-QUIC-API-0011` covers the shared runtime capability marker on `QuicConnection` and `QuicListener`.
- `REQ-QUIC-API-0012` defines and now lands the narrow public client-policy carrier `QuicClientConnectionOptions.PeerCertificatePolicy` with the `QuicPeerCertificatePolicy` payload for exact pinned peer identity and explicit trust material, and it keeps that carrier separate from the mainstream BCL-shaped validation path.
- `REQ-QUIC-API-0013` now lands the mainstream standard client-validation path on the existing `SslClientAuthenticationOptions` carrier, honoring `TargetHost`, `CertificateChainPolicy`, `CertificateRevocationCheckMode`, and callback overrides while keeping `QuicPeerCertificatePolicy` as the separate exact-pinning floor.

## Public Member Shape

The first slice keeps the consumer contract intentionally narrow:

- `QuicConnection` is the connection-lifetime facade over the runtime seam and exposes the client connect entry point.
- `QuicConnection` now also exposes the narrow inbound-stream accept and outbound-stream open entry points on the established loopback path.
- `QuicStream` is the stream-lifetime facade over the stream-state seam.
- `QuicStream` now exposes a narrow read/write-side capability, `ReadsClosed` and `WritesClosed`, and the corresponding write/completion plus `Abort(QuicAbortDirection.Read, ...)` / `Abort(QuicAbortDirection.Write, ...)` behavior on send-capable streams.
- `QuicConnectionOptions` is the shared bag for connection close/error defaults, timeouts, and receive-window knobs.
- `QuicConnectionOptions.StreamCapacityCallback` is the narrow outbound stream-capacity callback seam.
- `QuicReceiveWindowSizes` carries the configured receive-window values.
- `QuicException` carries the close/error classification.
- `QuicAbortDirection`, `QuicError`, `QuicStreamType`, and `QuicStreamCapacityChangedArgs` are the public classification/payload types used by the facade.
- `QuicConnection.IsSupported` and `QuicListener.IsSupported` are shared runtime capability markers for the supported managed loopback slice.
- The current client-input slice uses `QuicClientConnectionOptions.PeerCertificatePolicy` plus `QuicPeerCertificatePolicy` for the exact-pinning floor, while the mainstream `SslClientAuthenticationOptions` validation path honors `TargetHost`, `CertificateChainPolicy`, `CertificateRevocationCheckMode`, and `RemoteCertificateValidationCallback` on the same client carrier.

The public types do not introduce new endpoint or TLS wrapper abstractions in this slice. `QuicListener`, `QuicListenerOptions`, `QuicServerConnectionOptions`, `QuicClientConnectionOptions`, `QuicPeerCertificatePolicy`, `QuicStreamCapacityChangedArgs`, and `QuicConnectionOptions.StreamCapacityCallback` are now part of the approved facade.

## Listener And Client Split

The listener entry points are now part of this slice.

- The connection/listener/client slice reuses `QuicConnectionRuntime`, `QuicConnectionStreamState`, `QuicListenerHost`, `QuicConnectionRuntimeEndpoint`, `QuicConnectionEndpointHost`, and `QuicClientConnectionHost` directly.
- Listener startup and listener acceptance are honest and backed by the internal listener host.
- Client connect now starts a real client host/runtime shell and completes on the supported positive loopback boundary through the existing host seams, with Initial/DCID bootstrap, inbound Initial handling, and listener-side datagram admission already in place.
- The shared `IsSupported` marker is backed by one cached internal capability probe that checks the runtime prerequisites the supported managed slice already needs.
- Stream entry now reuses the same runtime and stream-state seams, plus a minimal 1-RTT short-header stream-control path, so the supported loopback connection can open and accept a real `QuicStream` facade and publish bytes plus EOF on the supported writable side while honoring the narrow read/write abort pair without surfacing the broader abort-heavy pipeline.
- The stream-capacity callback now reuses the same runtime and stream-state seams by projecting the initial peer stream-limit increments committed from transport parameters, later real peer `MAX_STREAMS` growth on the supported active loopback path, and the narrow close-driven release path where the runtime emits one real `MAX_STREAMS` increment only after a peer-initiated stream reaches the supported locally closed state.
- The supported `SslClientAuthenticationOptions` subset is standard-shaped on the mainstream path: non-empty ALPN, TLS 1.3 or the default protocol selection, `TargetHost` when supplied, `CertificateChainPolicy` when supplied, `CertificateRevocationCheckMode` delegation, and `RemoteCertificateValidationCallback` overrides. Unsupported broader client-auth settings, cipher-suite policies, and resumption/renegotiation knobs outside the current slice are still rejected deterministically instead of being ignored.
- Broader stream-management parity and any close-driven release behavior outside that supported locally closed subset remain deferred until the fuller stream-capacity path exists end to end.

## Standard Client Validation

The mainstream client-validation question is now closed on the existing `SslClientAuthenticationOptions` carrier.

- `TargetHost` is honored through BCL hostname matching when supplied.
- `CertificateChainPolicy` is honored through BCL `X509Chain` trust evaluation when supplied.
- `CertificateRevocationCheckMode` is delegated into the chain policy when no explicit chain policy is supplied.
- `RemoteCertificateValidationCallback` still receives the built chain and computed policy errors and can override acceptance in the standard BCL manner.
- `QuicClientConnectionOptions.PeerCertificatePolicy` / `QuicPeerCertificatePolicy` remains the separate exact-pinning floor.
- Mixed configuration between the exact-pinning floor and the standard validation inputs is rejected so the supported boundary stays honest.

This does not imply a new QUIC-specific validation policy type, `TargetHostName` public projection, broader client-auth, `0-RTT`, key update, transfer, or retry.

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

The only intentional deviation in this slice is that `IsSupported` is defined as a narrower managed capability marker rather than a native MsQuic availability flag, and combined `Abort(Both, ...)` remains unsupported until a combined read/write abort slice exists.

The repo-specific rule is that the richer internal transport engine stays hidden behind the consumer facade, the supported client TLS/auth subset is explicit and reject-first, and the public surface does not grow into a general middleware model.

## Trace Links

- Specification: `../../specs/requirements/quic/SPEC-QUIC-API.json`
- Architecture: `../../specs/architecture/quic/ARC-QUIC-API-0001.json`
- Work item: `../../specs/work-items/quic/WI-QUIC-API-0001.json`
- Verification: `../../specs/verification/quic/VER-QUIC-API-0001.json`

# Incursa.Quic Public API Gap Matrix

This note maps the current `Incursa.Quic` implementation against the public surface defined by:

- `docs/design/quic-public-api.md`
- `specs/requirements/quic/SPEC-QUIC-API.json`
- `specs/architecture/quic/ARC-QUIC-API-0001.json`
- `specs/work-items/quic/WI-QUIC-API-0001.json`
- `specs/verification/quic/VER-QUIC-API-0001.json`

This is a planning artifact only. It does not change code.

## A. Intended Public API Elements Evaluated

- `QuicConnection.IsSupported`
- `QuicListener.IsSupported`
- `QuicConnection`
- `QuicListener`
- `QuicStream`
- `QuicConnectionOptions`
- `QuicClientConnectionOptions`
- `QuicPeerCertificatePolicy`
- `QuicServerConnectionOptions`
- `QuicListenerOptions`
- `QuicReceiveWindowSizes`
- `QuicAbortDirection`
- `QuicError`
- `QuicException`
- `QuicStreamType`
- `QuicStreamCapacityChangedArgs`
- `QuicConnection.ConnectAsync(...)`
- `QuicListener.ListenAsync(...)`
- `QuicListener.AcceptConnectionAsync(...)`
- `QuicConnection.AcceptInboundStreamAsync(...)`
- `QuicConnection.OpenOutboundStreamAsync(...)`
- `QuicConnection.CloseAsync(...)`
- `QuicConnection.DisposeAsync(...)`
- `QuicStream` read/write/EOF/close/dispose/cancellation semantics
- `QuicConnectionOptions.StreamCapacityCallback`
- `QuicListenerOptions.ConnectionOptionsCallback`

## Cross-Cutting Finding

The approved public facade is now in place, and the current slice includes narrow but real client-entry establishment, stream-entry, write/completion, a narrow `RESET_STREAM` / `STOP_SENDING` abort pair, the shared `IsSupported` capability marker, and the stream-capacity callback boundary. The remaining gaps are behavioral rather than boundary-shape gaps: fuller client TLS/auth parity, combined `Abort(Both, ...)`, and the broader stream-management follow-ons.

- `src/Incursa.Quic/PublicAPI.Unshipped.txt` now matches the approved public facade instead of leaking helper, frame, runtime, and transport types.
- `QuicStreamType` is now the approved direction-only `Bidirectional` / `Unidirectional` model.
- `QuicConnectionLifecycleState` and `QuicIdleTimeoutState` are no longer part of the public facade.
- The listener/server entry points are now promoted on top of a small internal host shell, and the client entry point is present as a pending/cancelable shell over the existing endpoint-host/runtime seams.

That boundary trim is complete for this slice; the remaining work is about stream behavior and the remaining client API follow-ons.

## B. Gap Matrix

| Concept | Category | Current implementation | Why it lands here |
|---|---|---|---|
| Public boundary trim | 0. Closed | The analyzer file now matches the approved facade, and the helper/runtime/wire surface is back behind the boundary. | The remaining work is behavioral, not surface-shape enforcement. |
| `QuicConnection` family | 1. Implemented at the approved boundary | `QuicConnectionRuntime` already owns phase, close/drain, timers, TLS bridge state, stream registry, and send/recovery, and `QuicConnection.ConnectAsync(...)` now has the supported positive loopback establishment boundary on the existing client host/runtime seams. The same runtime/stream-state seam now backs the narrow active-loopback `AcceptInboundStreamAsync(...)`, `OpenOutboundStreamAsync(...)`, supported write/completion boundary, the narrow `RESET_STREAM` / `STOP_SENDING` abort pair, the shared `IsSupported` capability marker, and the narrow stream-capacity callback subset over a minimal 1-RTT short-header stream-control path with later real peer `MAX_STREAMS` growth and real peer stream-close-driven capacity release on the active-loopback path. | Endpoint metadata, combined `Abort(Both, ...)`, and the broader stream-management follow-ons stay out of scope. |
| `QuicListener` family | 1. Implemented at the approved boundary | `QuicListenerHost` binds a UDP socket, owns the accept queue, and bridges the narrow callback into provisional `QuicConnection` instances. | Listener startup and accept are now honest and narrow; the next gaps are on the client and stream sides. |
| `QuicStream` family | 1. Implemented at the approved boundary | `QuicConnectionStreamState` already tracks send/receive state, final size, reset handling, flow control, stream snapshots, and the narrow peer-stream openness needed for the supported stream-entry slice, and `QuicStream` now has a real supported write/completion lane plus a real `RESET_STREAM` / `STOP_SENDING`-backed `Abort(QuicAbortDirection.Write, ...)` / `Abort(QuicAbortDirection.Read, ...)` pair on the active loopback path. | The read-side facade is promoted, the supported stream-entry/write-completion/read-write-abort boundary is real, and the remaining follow-ons are `Abort(Both, ...)` plus later stream-management evolution. |
| `QuicConnectionOptions` / `QuicReceiveWindowSizes` | 1. Implemented at the approved boundary | Internal state already carries the numerical flow-control and idle-timeout knobs through `QuicConnectionStreamStateOptions`, `QuicIdleTimeoutState`, and `QuicConnectionRuntime`. | The remaining work is not the option bags themselves but the follow-on stream and establishment features. |
| `QuicClientConnectionOptions` | 1. Implemented at the approved boundary | `QuicConnectionRuntimeEndpoint`, `QuicConnectionEndpointHost`, and the managed TLS bridge already provide the client shell, the supported positive loopback establishment boundary, and a peer-certificate acceptance seam. The supported client input now includes `QuicClientConnectionOptions.PeerCertificatePolicy` with `QuicPeerCertificatePolicy.ExactPeerLeafCertificateDer` and `ExplicitTrustMaterialSha256` for the exact-pinning floor, and the mainstream `SslClientAuthenticationOptions` path now honors `TargetHost`, `CertificateChainPolicy`, `CertificateRevocationCheckMode`, and callback overrides on the existing client carrier. | The standard BCL validation path is now on the existing client carrier; the exact-pinning floor remains separate, and broader client-auth, transfer, or retry support is still out of scope. |
| `QuicPeerCertificatePolicy` | 1. Implemented at the approved boundary | `QuicPeerCertificatePolicy` is the narrow bytes-only carrier for exact pinned peer identity and explicit trust material, and `QuicClientConnectionOptions.PeerCertificatePolicy` feeds it into the existing internal snapshot/fail-closed seam. The exact-pinning floor stays mutually exclusive with the mainstream BCL validation path. | It stays narrower than the mainstream validation path's `TargetHost` / `CertificateChainPolicy` inputs plus broader client-auth, transfer, and retry. |
| `QuicServerConnectionOptions` | 1. Implemented at the approved boundary | `QuicServerConnectionOptions` now exposes `ServerAuthenticationOptions` plus the server-side stream defaults consumed by the listener callback, and the managed server path now honors `ClientCertificateRequired` on the live path through the existing callback-driven acceptance seam while keeping broader chain/revocation customization deferred. | The carrier exists, and the narrow server-side client-auth floor now lands on that same carrier without widening the public surface. |
| `QuicListenerOptions` | 1. Implemented at the approved boundary | `QuicListenerOptions` now carries the endpoint, backlog, ALPN list, and narrow server connection-options callback, and `ListenAsync(...)` validates them before binding. | Listener configuration is now live. |
| `QuicError` / `QuicException` / `QuicAbortDirection` | 1. Implemented at the approved boundary | The runtime already has `QuicTransportErrorCode`, internal close metadata, and terminal state, and the public error/abort surface is now present. | The remaining work is in the stream and establishment paths, not the error vocabulary. |
| `QuicStreamType` | 1. Implemented at the approved boundary | `QuicStreamType` now uses the approved direction-only `Bidirectional` and `Unidirectional` values. | The older initiator quadrants are gone from the public enum. |
| `QuicStreamCapacityChangedArgs` | 1. Implemented at the approved boundary | The public args type and `QuicConnectionOptions.StreamCapacityCallback` now exist, and the callback is backed by real peer stream-limit commit bookkeeping on the supported loopback and active-loopback paths. | The supported subset is intentionally narrow: it reports the initial non-zero outbound stream-open capacity increments committed from peer transport parameters plus later real peer `MAX_STREAMS` growth and real peer stream-close-driven capacity release on the supported active loopback path. |
| `QuicConnection.IsSupported` / `QuicListener.IsSupported` | 1. Implemented at the approved boundary | The two public static properties now share one cached runtime-capability probe over the supported managed slice prerequisites. | The marker is intentionally narrow and does not imply feature completeness, interop-runner readiness, 0-RTT, key update, or combined `Abort(Both, ...)`. |

## C. 10 Highest-Value Gaps

1. Promote the remaining combined `Abort(Both, ...)` and broader abort-heavy follow-on.
2. Keep the standard BCL client-validation path and the exact-pinning floor covered by focused requirement-home tests, including mixed-mode rejection.
3. Keep the remainder of the packet, frame, transport-parameter, recovery, congestion, and stream-identity helpers internal.

## D. Gaps That Must Be Solved Before an Honest First Public Preview

- The public boundary is trimmed; the remaining preview blocker is honest behavior, not exposed helper types.
- `QuicConnection` now has the supported positive establishment path, the narrow active-loopback stream-entry path, and the narrow stream-capacity callback path.
- `QuicStream` now has a real supported write/completion lane and a narrow `RESET_STREAM` / `STOP_SENDING`-backed abort pair, but it still needs the combined `Abort(Both, ...)` follow-on before the broader stream contract can be honest.
- The stream-capacity callback surface is now present on the supported loopback and active-loopback paths, including real stream-close-driven capacity release on the supported active-loopback path.
- The client TLS/auth subset now includes the mainstream standard validation path on the existing carrier, while the exact-pinning floor remains separate and mixed-mode configuration is rejected.

## E. Smallest Next Implementation Slice

The smallest high-value slice after this one is the richer stream-behavior follow-on:

- Add the combined `Abort(Both, ...)` and broader abort-heavy follow-on as needed.
- Leave any remaining broader stream-management follow-on work for after the current callback subset.

## F. Current State Summary

### Already Closest To Real

- `QuicConnectionRuntime` is the most complete internal runtime piece.
- `QuicConnectionStreamState` is the strongest internal stream-state implementation.
- `QuicTransportTlsBridgeDriver` and `QuicTlsKeySchedule` already carry a narrow TLS proof slice.
- `QuicListenerHost` is the closest thing to a server ingress shell, but it is still internal and narrow.
- `QuicConnectionRuntimeEndpoint`, `QuicConnectionEndpointHost`, and `QuicClientConnectionHost` are the closest connection-oriented socket ingress shell code, and they now back the supported positive client establishment boundary.

### Mostly Internal-Only Today

- Stream entry points are now real on the narrow active-loopback boundary, and the supported write/completion plus narrow read/write abort pair is also real; the remaining blocker is the combined `Abort(Both, ...)` follow-on.
- Broader stream-management follow-ons.

### Main Blockers By Type

- Richer TLS policy / trust / validation: hostname validation, chain policy, and the fuller client-side auth contract.
- Missing behavior: combined `Abort(Both, ...)` and the broader abort-heavy follow-on.

### Recommended Next Slice

Promote the combined `Abort(Both, ...)` and any remaining broader stream-management follow-ons next, backed by the existing runtime, TLS bridge, and narrow stream-entry plus stream-capacity boundaries, so they can build on a real connection instead of a pending shell.

For the broader cleanup / interop-prep sequence beyond this public-surface matrix, see `docs/design/quic-interop-prep-plan.md`. This matrix stays limited to the public boundary and the nearest follow-on gaps.

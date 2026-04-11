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

The approved public facade is now in place, and the current slice is connection-first with a narrow client-entry shell. The remaining gaps are behavioral rather than boundary-shape gaps: positive client establishment, stream entry points, the capacity callback surface, and fuller client TLS/auth parity.

- `src/Incursa.Quic/PublicAPI.Unshipped.txt` now matches the approved public facade instead of leaking helper, frame, runtime, and transport types.
- `QuicStreamType` is now the approved direction-only `Bidirectional` / `Unidirectional` model.
- `QuicConnectionLifecycleState` and `QuicIdleTimeoutState` are no longer part of the public facade.
- The listener/server entry points are now promoted on top of a small internal host shell, and the client entry point is present as a pending/cancelable shell over the existing endpoint-host/runtime seams.

That boundary trim is complete for this slice; the remaining work is about honest establishment and stream behavior.

## B. Gap Matrix

| Concept | Category | Current implementation | Why it lands here |
|---|---|---|---|
| Public boundary trim | 0. Closed | The analyzer file now matches the approved facade, and the helper/runtime/wire surface is back behind the boundary. | The remaining work is behavioral, not surface-shape enforcement. |
| `QuicConnection` family | 2. Partially implemented behind internal seams | `QuicConnectionRuntime` already owns phase, close/drain, timers, TLS bridge state, stream registry, and send/recovery, and `QuicConnection.ConnectAsync(...)` is now present as the client-entry shell. | The positive client establishment path, `IsSupported`, `AcceptInboundStreamAsync`, `OpenOutboundStreamAsync`, endpoint metadata, and the stream-entry follow-on stay deferred. |
| `QuicListener` family | 1. Implemented at the approved boundary | `QuicListenerHost` binds a UDP socket, owns the accept queue, and bridges the narrow callback into provisional `QuicConnection` instances. | Listener startup and accept are now honest and narrow; the next gaps are on the client and stream sides. |
| `QuicStream` family | 2. Partially implemented behind internal seams | `QuicConnectionStreamState` already tracks send/receive state, final size, reset handling, flow control, and stream snapshots. | The read-side facade is promoted, but the write-heavy contract and stream-action pipeline stay deferred. |
| `QuicConnectionOptions` / `QuicReceiveWindowSizes` | 1. Implemented at the approved boundary | Internal state already carries the numerical flow-control and idle-timeout knobs through `QuicConnectionStreamStateOptions`, `QuicIdleTimeoutState`, and `QuicConnectionRuntime`. | The remaining work is not the option bags themselves but the follow-on stream and establishment features. |
| `QuicClientConnectionOptions` | 1. Implemented at the approved boundary | `QuicConnectionRuntimeEndpoint`, `QuicConnectionEndpointHost`, and the managed TLS bridge already provide the client shell and a peer-certificate acceptance seam. | The supported subset is narrow and reject-first; positive establishment and richer trust policy remain deferred. |
| `QuicServerConnectionOptions` | 1. Implemented at the approved boundary | `QuicServerConnectionOptions` now exposes `ServerAuthenticationOptions` plus the server-side stream defaults consumed by the listener callback. | The server-side options bag is in place for the listener slice. |
| `QuicListenerOptions` | 1. Implemented at the approved boundary | `QuicListenerOptions` now carries the endpoint, backlog, ALPN list, and narrow server connection-options callback, and `ListenAsync(...)` validates them before binding. | Listener configuration is now live. |
| `QuicError` / `QuicException` / `QuicAbortDirection` | 1. Implemented at the approved boundary | The runtime already has `QuicTransportErrorCode`, internal close metadata, and terminal state, and the public error/abort surface is now present. | The remaining work is in the stream and establishment paths, not the error vocabulary. |
| `QuicStreamType` | 1. Implemented at the approved boundary | `QuicStreamType` now uses the approved direction-only `Bidirectional` and `Unidirectional` values. | The older initiator quadrants are gone from the public enum. |
| `QuicStreamCapacityChangedArgs` | 5. Missing entirely | There is no public args type and no public callback surface today. The internal stream bookkeeping only emits blocked-frame / flow-control facts. | The callback payload and the callback hook both need to be introduced, even though the underlying capacity accounting exists. |

## C. 10 Highest-Value Gaps

1. Land the positive client establishment path, including the Initial/DCID bootstrap boundary and inbound Initial handling.
2. Promote the stream entry points and the write-heavy stream-action pipeline.
3. Add `QuicStreamCapacityChangedArgs` and the capacity-callback surface.
4. Decide whether `QuicConnection.IsSupported` and `QuicListener.IsSupported` stay deferred or need a tiny honest shim.
5. Broaden the client TLS/auth contract only if it can be done honestly, otherwise keep rejecting unsupported settings.
6. Keep the remaining `QuicStream` write-side and abort-heavy semantics narrow until the stream-action pipeline exists.
7. Keep the remainder of the packet, frame, transport-parameter, recovery, congestion, and stream-identity helpers internal.

## D. Gaps That Must Be Solved Before an Honest First Public Preview

- The public boundary is trimmed; the remaining preview blocker is honest behavior, not exposed helper types.
- `QuicConnection` still needs a positive establishment path before the stream entry-point slice can build on top of it.
- `QuicStream` still needs the write-heavy action pipeline before the full stream contract can be honest.
- The stream-capacity callback surface is still deferred.
- The client TLS/auth subset is intentionally narrow until the trust-store and hostname-validation story exists.

## E. Smallest Next Implementation Slice

The smallest high-value slice after this one is the positive client establishment path:

- Add the Initial/DCID bootstrap and inbound Initial handling needed for a real client/server loopback boundary.
- Keep `QuicConnection.ConnectAsync(...)` honest by returning a connection only when the supported establishment boundary is actually reached.
- Leave `QuicStreamCapacityChangedArgs` and the stream entry-point follow-on for after the connection boundary is real.

## F. Current State Summary

### Already Closest To Real

- `QuicConnectionRuntime` is the most complete internal runtime piece.
- `QuicConnectionStreamState` is the strongest internal stream-state implementation.
- `QuicTransportTlsBridgeDriver` and `QuicTlsKeySchedule` already carry a narrow TLS proof slice.
- `QuicListenerHost` is the closest thing to a server ingress shell, but it is still internal and narrow.
- `QuicConnectionRuntimeEndpoint`, `QuicConnectionEndpointHost`, and `QuicClientConnectionHost` are the closest connection-oriented socket ingress shell code.

### Mostly Internal-Only Today

- Positive client establishment.
- Stream entry points and write-heavy stream action handling.
- Stream-capacity callback surface.
- `QuicConnection.IsSupported` and `QuicListener.IsSupported`.

### Main Blockers By Type

- Positive client establishment and richer TLS policy / trust / validation: Initial/DCID bootstrap, listener-side datagram admission, hostname validation, chain policy, and the fuller client-side auth contract.
- Missing behavior: stream entry points, stream completion tasks, and the capacity callback surface.

### Recommended Next Slice

Promote the positive client establishment slice next, backed by the existing runtime and TLS bridge, so the stream entry-point slice can build on a real connection boundary instead of a pending shell.

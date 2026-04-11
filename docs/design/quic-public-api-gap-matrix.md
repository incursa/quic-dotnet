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

The current public surface is still a helper-layer staging surface, but the implementation slice is now connection-first.

- `src/Incursa.Quic/PublicAPI.Unshipped.txt` still exposes many helper, frame, runtime, and transport types that `REQ-QUIC-API-0001` says must stay internal.
- `QuicStreamType` is public today, but its values are the old client/server initiator quadrants instead of the approved direction-only `Bidirectional` / `Unidirectional` model.
- `QuicConnectionLifecycleState` and `QuicIdleTimeoutState` are still public helper types today, which is outside the approved consumer facade.
- The listener/server entry points are now promoted on top of a small internal host shell; client connect and the fuller TLS-auth wrappers remain deferred so the next slice can stay focused on client policy and trust.

That boundary trim is a prerequisite for any honest preview.

## B. Gap Matrix

| Concept | Category | Current implementation | Why it lands here |
|---|---|---|---|
| Public boundary trim | 5. Missing entirely | The analyzer file still leaks helper/runtime/wire types, and several helper concepts are public today. | The approved consumer facade is not yet enforced. The spec says the extra helper surface must remain internal. |
| `QuicConnection` family | 2. Partially implemented behind internal seams | `QuicConnectionRuntime` already owns phase, close/drain, timers, TLS bridge state, stream registry, and send/recovery. | The first slice can promote the connection-lifetime facade and close/dispose/error projection now, but `IsSupported`, `ConnectAsync`, `AcceptInboundStreamAsync`, `OpenOutboundStreamAsync`, and endpoint metadata stay deferred. |
| `QuicListener` family | 2. Partially implemented behind internal seams | `QuicListenerHost` now binds a UDP socket, owns the accept queue, and bridges the narrow callback into provisional `QuicConnection` instances. | The listener server surface is now honest and narrow; client connect and the fuller client-auth contract stay deferred. |
| `QuicStream` family | 2. Partially implemented behind internal seams | `QuicConnectionStreamState` already tracks send/receive state, final size, reset handling, flow control, and stream snapshots. | The first slice can promote the public `Stream` wrapper, stream identity, EOF/read-side projection, and lifetime tasks, but the write-heavy contract and stream-action pipeline stay deferred. |
| `QuicConnectionOptions` / `QuicReceiveWindowSizes` | 2. Partially implemented behind internal seams | Internal state already carries the numerical flow-control and idle-timeout knobs through `QuicConnectionStreamStateOptions`, `QuicIdleTimeoutState`, and `QuicConnectionRuntime`. | The shared connection option bag and receive-window values are live, while the client connect surface, client-auth wrappers, and stream-capacity callback stay deferred. |
| `QuicClientConnectionOptions` | 4. Blocked mainly by TLS policy / trust / validation work | `QuicTlsTransportBridgeDriver` currently supports a client-role pinned peer leaf SHA-256 policy and the managed proof slice, not a public `SslClientAuthenticationOptions`-backed contract. | The client surface is intentionally deferred to the next slice. |
| `QuicServerConnectionOptions` | 2. Partially implemented behind internal seams | `QuicServerConnectionOptions` now exposes `ServerAuthenticationOptions` plus the server-side stream defaults consumed by the listener callback. | The server-side options bag is in place for the listener slice; the client-side auth wrapper stays deferred. |
| `QuicListenerOptions` | 2. Partially implemented behind internal seams | `QuicListenerOptions` now carries the endpoint, backlog, ALPN list, and narrow server connection-options callback, and `ListenAsync(...)` validates them before binding. | Listener configuration is now live; client connect remains deferred. |
| `QuicError` / `QuicException` / `QuicAbortDirection` | 2. Partially implemented behind internal seams | The runtime already has `QuicTransportErrorCode`, internal close metadata, terminal state, and stream send/receive state machines. | The consumer-facing error/abort classification surface is still missing even though the internal terminal-state machinery exists. |
| `QuicStreamType` | 2. Partially implemented behind internal seams | `QuicStreamType` is public today, but it still exposes `ClientInitiatedBidirectional`, `ServerInitiatedBidirectional`, `ClientInitiatedUnidirectional`, and `ServerInitiatedUnidirectional`. | The internal stream model already distinguishes direction and initiator separately. The public enum still needs to be collapsed to the approved direction-only shape. |
| `QuicStreamCapacityChangedArgs` | 5. Missing entirely | There is no public args type and no public callback surface today. The internal stream bookkeeping only emits blocked-frame / flow-control facts. | The callback payload and the callback hook both need to be introduced, even though the underlying capacity accounting exists. |

## C. 10 Highest-Value Gaps

1. Trim the public API boundary so helper/runtime/wire types stop leaking through the analyzer surface.
2. Promote the connection-lifetime `QuicConnection` facade over the existing runtime and terminal-state machinery.
3. Promote the `QuicStream` facade over the existing stream-state machinery, but keep the write-heavy path deferred until the stream-action pipeline exists.
4. Add `QuicConnectionOptions` and `QuicReceiveWindowSizes` as the shared connection-side configuration bags.
5. Add the public error/abort surface: `QuicError`, `QuicException`, and `QuicAbortDirection`.
6. Correct `QuicStreamType` to the direction-only public model.
7. Keep `QuicClientConnectionOptions`, `QuicStreamCapacityChangedArgs`, and the client-connect surface for the next slice.

## D. Gaps That Must Be Solved Before an Honest First Public Preview

- The public boundary must be trimmed first. Shipping preview with helper-layer types still public would contradict `REQ-QUIC-API-0001`.
- `QuicConnection` and `QuicStream` need their remaining lifecycle surface completed, and the listener shell must stay honest and narrow.
- Client connect and the client TLS options must be real public contracts before the next preview, not raw-derivation seams.
- The public error and abort surfaces must exist so close, reset, and shutdown outcomes are visible without exposing internal state.
- `QuicStreamType` must be corrected to the approved direction-only model.
- The stream-capacity callback surface must exist if `QuicConnectionOptions` is going to expose it.

## E. Smallest Next Implementation Slice

The smallest high-value slice is the client connection establishment surface:

- Add `QuicConnection.ConnectAsync(...)` and `QuicClientConnectionOptions`.
- Wire that slice to the existing `QuicConnectionRuntime`, `QuicConnectionStreamState`, and TLS bridge machinery.
- Add negative-access and API-diff tests to prove the helper/runtime surface is no longer public.
- Leave the client-auth policy/trust surface, `QuicStreamCapacityChangedArgs`, and any broader transport features for the next slice after that.

## F. Current State Summary

### Already Closest To Real

- `QuicConnectionRuntime` is the most complete internal runtime piece.
- `QuicConnectionStreamState` is the strongest internal stream-state implementation.
- `QuicTransportTlsBridgeDriver` and `QuicTlsKeySchedule` already carry a narrow TLS proof slice.
- `QuicListenerHost` is the closest thing to a server ingress shell, but it is still internal and narrow.
- `QuicConnectionRuntimeEndpoint` and `QuicConnectionEndpointHost` remain the closest connection-oriented socket ingress shell code.

### Mostly Internal-Only Today

- Public connection/stream facade types.
- Public listener surface and listener options.
- Public error and abort surface.
- Public stream-capacity callback surface.
- Public client TLS auth option wrappers.

### Main Blockers By Type

- Client connection and TLS policy / trust / validation: `QuicConnection.ConnectAsync`, `QuicClientConnectionOptions`, and the client-side auth wrapper.
- Missing behavior: public facade promotion, stream completion tasks, error/abort projection, `QuicStreamType` correction, and the capacity callback surface.

### Recommended Next Slice

Promote the client connection surface next, backed by the existing runtime and TLS bridge, while trimming the public API analyzer surface in the same slice. That gives the highest leverage on the code that is already closest to real and keeps the remaining TLS/auth work isolated for the follow-up slice.

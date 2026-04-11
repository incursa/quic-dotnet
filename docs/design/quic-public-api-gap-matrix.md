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
- The listener and TLS-auth entry points are deliberately deferred for this pass so the first consumer slice can stay honest and stay rooted in `QuicConnectionRuntime` plus `QuicConnectionStreamState`.

That boundary trim is a prerequisite for any honest preview.

## B. Gap Matrix

| Concept | Category | Current implementation | Why it lands here |
|---|---|---|---|
| Public boundary trim | 5. Missing entirely | The analyzer file still leaks helper/runtime/wire types, and several helper concepts are public today. | The approved consumer facade is not yet enforced. The spec says the extra helper surface must remain internal. |
| `QuicConnection` family | 2. Partially implemented behind internal seams | `QuicConnectionRuntime` already owns phase, close/drain, timers, TLS bridge state, stream registry, and send/recovery. | The first slice can promote the connection-lifetime facade and close/dispose/error projection now, but `IsSupported`, `ConnectAsync`, `AcceptInboundStreamAsync`, `OpenOutboundStreamAsync`, and endpoint metadata stay deferred. |
| `QuicListener` family | 3. Blocked mainly by endpoint-host / socket wiring | `QuicConnectionRuntimeEndpoint.ReceiveDatagram()` and `QuicConnectionEndpointHost.RunAsync()` already provide connected-UDP ingress and routing. The interop harness still says `handshake`, `transfer`, and `retry` are unsupported. | The listener shell, accept queue, and callback wiring stay in the next slice. |
| `QuicStream` family | 2. Partially implemented behind internal seams | `QuicConnectionStreamState` already tracks send/receive state, final size, reset handling, flow control, and stream snapshots. | The first slice can promote the public `Stream` wrapper, stream identity, EOF/read-side projection, and lifetime tasks, but the write-heavy contract and stream-action pipeline stay deferred. |
| `QuicConnectionOptions` / `QuicReceiveWindowSizes` | 2. Partially implemented behind internal seams | Internal state already carries the numerical flow-control and idle-timeout knobs through `QuicConnectionStreamStateOptions`, `QuicIdleTimeoutState`, and `QuicConnectionRuntime`. | The shared connection option bag and receive-window values can ship now, but the listener callback, TLS-auth wrappers, and stream-capacity callback stay deferred. |
| `QuicClientConnectionOptions` | 4. Blocked mainly by TLS policy / trust / validation work | `QuicTlsTransportBridgeDriver` currently supports a client-role pinned peer leaf SHA-256 policy and the managed proof slice, not a public `SslClientAuthenticationOptions`-backed contract. | The client surface is intentionally deferred to the next slice. |
| `QuicServerConnectionOptions` | 4. Blocked mainly by TLS policy / trust / validation work | `QuicTlsKeySchedule` can synthesize a server flight from raw DER and a raw signing-key seam. | The server surface is intentionally deferred to the next slice. |
| `QuicListenerOptions` | 3. Blocked mainly by endpoint-host / socket wiring | There is no listener facade, no bind/listen accept queue, and no listener callback surface yet. | Listener configuration stays behind the missing socket/listener shell. |
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
7. Keep `QuicListener`, `QuicListenerOptions`, `QuicClientConnectionOptions`, `QuicServerConnectionOptions`, `QuicStreamCapacityChangedArgs`, and the connect/listen/accept entry points for the next slice.

## D. Gaps That Must Be Solved Before an Honest First Public Preview

- The public boundary must be trimmed first. Shipping preview with helper-layer types still public would contradict `REQ-QUIC-API-0001`.
- `QuicConnection`, `QuicListener`, and `QuicStream` need their public facade types and lifecycle methods in place.
- Listener socket wiring must exist. `ListenAsync` and `AcceptConnectionAsync` need a real bind/listen/accept shell, not only the internal connected-UDP ingress path.
- The client and server TLS options must be real public contracts, not raw-derivation seams.
- The public error and abort surfaces must exist so close, reset, and shutdown outcomes are visible without exposing internal state.
- `QuicStreamType` must be corrected to the approved direction-only model.
- The stream-capacity callback surface must exist if `QuicConnectionOptions` is going to expose it.

## E. Smallest Next Implementation Slice

The smallest high-value slice is the connection-side public facade:

- Add `QuicConnection`, `QuicStream`, `QuicConnectionOptions`, `QuicReceiveWindowSizes`, `QuicError`, `QuicException`, `QuicAbortDirection`, and the `QuicStreamType` correction.
- Wire that slice to the existing `QuicConnectionRuntime`, `QuicConnectionStreamState`, and close/drain machinery.
- Add negative-access and API-diff tests to prove the helper/runtime surface is no longer public.
- Leave `QuicListener` socket/listen/accept wiring and the full TLS policy/trust surface for the next slice.

## F. Current State Summary

### Already Closest To Real

- `QuicConnectionRuntime` is the most complete internal runtime piece.
- `QuicConnectionStreamState` is the strongest internal stream-state implementation.
- `QuicTransportTlsBridgeDriver` and `QuicTlsKeySchedule` already carry a narrow TLS proof slice.
- `QuicConnectionRuntimeEndpoint` and `QuicConnectionEndpointHost` are the closest thing to socket ingress shell code, but they are still internal and connection-oriented.

### Mostly Internal-Only Today

- Listener surface and listener options.
- Public connection/stream facade types.
- Public error and abort surface.
- Public stream-capacity callback surface.
- Public TLS auth option wrappers.

### Main Blockers By Type

- Endpoint-host / socket wiring: `QuicListener`, `ListenAsync`, `AcceptConnectionAsync`, and the server-side accept shell.
- TLS policy / trust / validation: `QuicClientConnectionOptions` and `QuicServerConnectionOptions`.
- Missing behavior: public facade promotion, stream completion tasks, error/abort projection, `QuicStreamType` correction, and the capacity callback surface.

### Recommended Next Slice

Promote the connection-side consumer facade first, backed by the existing runtime, while trimming the public API analyzer surface in the same slice. That gives the highest leverage on the code that is already closest to real and keeps the listener/socket work isolated for the follow-up slice.

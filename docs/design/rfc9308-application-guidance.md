# RFC 9308 Application Guidance

This note records how application protocols should use the current Incursa QUIC and HTTP/3 surfaces in light of RFC 9308. RFC 9308 is informational guidance, so this document does not create new transport features by itself.

## Supported Boundary

- The public QUIC surface is the managed connection, stream, datagram, and listener facade documented in [`quic-public-api.md`](quic-public-api.md).
- HTTP/3 support is the bounded frame, stream-mapping, QPACK, and minimal request/response floor documented in [`../../src/Incursa.Quic.Http3/HTTP3-READINESS.md`](../../src/Incursa.Quic.Http3/HTTP3-READINESS.md).
- QUIC DATAGRAM support is the RFC 9221 transport floor. HTTP Datagrams, CONNECT-UDP, and MASQUE remain separate future features.

## 0-RTT And Replay Safety

The public API does not expose application 0-RTT. Internal early-data and resumption prerequisites do not make arbitrary application data replay-safe. Any future public 0-RTT API must be tied to an application profile that defines which requests are safe to replay, what server-side anti-replay state is required, and how rejected early data falls back to normal 1-RTT behavior.

Applications should treat current connections as 1-RTT application-data connections unless a later requirement explicitly says otherwise.

## Keep-Alive Versus Resumption

`QuicConnectionOptions.IdleTimeout` and `QuicConnectionOptions.KeepAliveInterval` are liveness controls for an established connection. They are not TLS session resumption, and they do not authorize 0-RTT application data. Applications should choose between keeping a connection alive and creating a new connection with resumption based on their own latency, resource, and replay-safety requirements.

## Stream Mapping

QUIC streams provide ordered, reliable byte streams. They do not carry application message boundaries or application roles by themselves. Protocol adapters must define which streams are control streams, request streams, response streams, upload streams, or other protocol roles.

For HTTP/3, the adapter owns the required control and QPACK stream mapping before opening request streams. Other application protocols need their own equivalent mapping document or code-level policy.

## Priority And Backpressure

`QuicStream.Priority` is a local send-scheduling hint. It is not HTTP/3 priority signaling and is not exchanged on the wire.

Applications should use `QuicConnectionOptions.StreamCapacityCallback` as the stream-limit backpressure signal. When stream capacity is exhausted, outbound stream opens can remain pending until the peer increases the stream limit. Applications should avoid designs that require a new stream to make progress while also withholding the reads or closes that would release capacity.

Flow-control blocked writes preserve stream state and report blocked-credit diagnostics. Applications should continue reading inbound data and should handle write failures or pending work as backpressure, not as a reason to stop consuming peer data.

## Migration And NAT Rebinding

The transport can classify address changes and validate candidate paths. A NAT rebinding or migration candidate is not promoted to the active path until validation succeeds. Applications should not infer peer identity or authorization solely from a UDP address tuple, and they should rely on connection-level authentication and transport validation.

The public API does not expose a general migration-control surface. Diagnostics and qlog output are the supported troubleshooting surfaces for migration and NAT rebinding behavior.

## Connection Termination

`QuicConnection.CloseAsync(long errorCode)` sends an application close code. That code belongs to the protocol layered over QUIC and is distinct from QUIC transport error codes. Stream abort codes are also application error codes.

Protocol adapters should document their application error-code registry and translate transport failures separately from application-layer failures.

## Endpoint Discovery, Versions, And Deployment

The QUIC facade does not implement endpoint discovery such as Alt-Svc, SVCB, or HTTPS records. Applications are responsible for endpoint discovery and fallback policy.

Version negotiation, compatible-version negotiation, QUIC v2 static support, and QUIC Bit greasing have their own traced RFC slices. Deploying a new version still needs an application/operator rollout plan that covers peer compatibility, fallback, diagnostics, and interop evidence.

## Applicability Status

| RFC 9308 topic | Status |
| --- | --- |
| Fallback | Application/deployment owned; no automatic fallback added |
| 0-RTT replay safety | Public app 0-RTT deferred until a replay-safe profile exists |
| Session resumption versus keep-alive | Documented as separate concerns |
| Stream mapping | Application-owned; HTTP/3 adapter has a bounded mapping |
| Priority | Local scheduling hint only; HTTP/3 priority signaling deferred |
| Ordered/reliable delivery | Satisfied by QUIC streams; message boundaries are application-owned |
| Flow-control deadlock prevention | Existing flow-control behavior plus RFC 9308 diagnostics/tests |
| Stream limits/backpressure | Existing stream-limit behavior plus RFC 9308 diagnostics/tests |
| Error propagation | Application close codes remain separate from transport errors |
| Migration/NAT rebinding | Candidate paths are validated before promotion |
| CID privacy/linkability | Randomized CID lifecycle exists; no broader timing-linkability guarantee is claimed |
| QoS/DSCP | No public DSCP API |
| Version deployment | Existing version slices; rollout guidance remains application/operator owned |
| QUIC DATAGRAM | RFC 9221 transport floor only; HTTP Datagram/MASQUE deferred |

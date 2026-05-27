# Application Protocol Guidance

This guide is for developers building application protocols on top of
`Incursa.Quic`. It applies the informational guidance in RFC 9308 to the
current implementation without turning every RFC 9308 sentence into a protocol
feature.

Trace sources:

- [`SPEC-QUIC-RFC9308`](../specs/requirements/quic/SPEC-QUIC-RFC9308.json)
- [`RFC 9308 classification`](design/rfc9308-rfc9312-spectrace-classification.md)
- [`RFC 9308 application guidance design note`](design/rfc9308-application-guidance.md)
- [RFC 9308 text](https://www.rfc-editor.org/rfc/rfc9308.html)

## Support Boundary

RFC 9308 is applicability guidance. Current behavior is still owned by the
normative transport, TLS, HTTP/3, QPACK, and DATAGRAM requirement families.
This guide describes how to use the supported surface honestly:

- QUIC streams provide ordered, reliable byte streams.
- QUIC DATAGRAM support is the RFC 9221 transport floor only.
- Public application 0-RTT is not exposed.
- Endpoint discovery and fallback policy are application owned.
- HTTP Datagrams, CONNECT-UDP, MASQUE, DSCP controls, and QUIC-LB are future
  or deployment-specific topics, not current runtime features.

## Streams

Use streams when the application needs reliable delivery, ordering within a
single byte sequence, independent cancellation, or explicit lifetime management.
A stream does not provide application message boundaries by itself. Application
protocols need their own mapping that says which streams are control streams,
request streams, response streams, upload streams, or other protocol roles.

For HTTP/3, stream mapping is owned by the HTTP/3 adapter and the RFC 9114 and
RFC 9204 requirement sets. For a new protocol directly over QUIC, document the
mapping before depending on stream IDs in code. Query stream properties exposed
by the API instead of inferring roles from future stream ID allocation.

Relevant SpecTrace item: `REQ-QUIC-RFC9308-S4P1-0001`.

## Datagrams

Use DATAGRAM only for messages where loss, reordering, and lack of retransmission
are acceptable to the application protocol. DATAGRAM payloads are not a shortcut
for reliable messages and do not replace streams when ordered delivery matters.

The current support boundary is QUIC DATAGRAM transport behavior from RFC 9221.
It does not claim HTTP Datagrams, CONNECT-UDP, or MASQUE support. Protocols that
need those layers must add separate traced requirements and verification.

Relevant SpecTrace item: `REQ-QUIC-RFC9308-S15-0001`.

## 0-RTT Replay Risk

The public API does not expose application 0-RTT. Internal resumption and early
data prerequisites do not make arbitrary application data replay safe.

If a future protocol enables 0-RTT, it needs a profile that defines exactly which
operations are safe to replay, how unsafe operations are rejected, and how the
client retries rejected early data over normal 1-RTT. Do not send
non-idempotent operations, authorization-changing operations, or ordered
operation sequences in 0-RTT unless that future profile explicitly allows them.

Relevant SpecTrace item: `REQ-QUIC-RFC9308-S3P1-0001`.

## Keep-Alive Versus Reconnect And Resumption

Keep-alive keeps an existing connection and network path active. Session
resumption is a way to reduce the cost of a later connection. They are separate
decisions.

Use `QuicConnectionOptions.IdleTimeout` and `KeepAliveInterval` only when the
application expects the connection to be useful after an idle period and the
extra traffic is worth the NAT, firewall, battery, and server resource cost.
For request/response protocols with long idle gaps, reconnecting later can be a
better design than keeping every connection warm.

Keep-alive does not authorize 0-RTT application data. Resumption does not remove
the need for a replay-safe 0-RTT profile.

Relevant SpecTrace item: `REQ-QUIC-RFC9308-S3P2-0001`.

## Flow Control And Stream-Limit Backpressure

Treat flow-control blocking and stream-limit exhaustion as backpressure, not as
deadlock conditions to work around with unbounded buffering.

For flow control:

- Continue reading inbound data so the transport can release credit.
- Design large messages so the receiver can consume them incrementally.
- Avoid waiting for an entire length-prefixed message before releasing receive
  credit when the message can exceed available stream or connection credit.
- Watch for `quic:flow_control_blocked` diagnostics when a writer cannot make
  progress because credit is exhausted.

For stream limits:

- Use `QuicConnectionOptions.StreamCapacityCallback` as the public capacity
  signal.
- Do not design a protocol where progress requires opening a new stream while
  existing streams are intentionally left unread or unclosed.
- Watch for `quic:stream_limit_blocked` diagnostics when stream creation is
  blocked by peer limits.

Relevant SpecTrace items: `REQ-QUIC-RFC9308-S4P4-0001`,
`REQ-QUIC-RFC9308-S4P5-0001`.

## Stream Priority

`QuicStream.Priority` is a local scheduling hint. It is not network-visible and
is not an HTTP/3 priority signal. If an application protocol needs peer-visible
priority, define that signal at the application layer and test it there.

Relevant SpecTrace item: `REQ-QUIC-RFC9308-S4P1-0001`.

## Graceful And Abrupt Termination

Use graceful stream completion when the application has finished sending a byte
sequence normally. Use stream aborts when the application intentionally cancels a
direction or asks the peer to stop sending. Protocols should document when each
case is valid.

`QuicConnection.CloseAsync(long errorCode)` sends an application close code. That
code belongs to the application protocol layered over QUIC and is distinct from
QUIC transport error codes. Stream abort codes are also application error codes.
Keep a clear registry for application error codes and avoid using transport
errors to describe application semantics.

Relevant SpecTrace item: `REQ-QUIC-RFC9308-S6-0001`.

## Connection Migration And NAT Rebinding

The transport can detect address changes and validate candidate paths. A NAT
rebinding or migration candidate is not promoted to the active path until path
validation succeeds.

Applications should not bind authentication, authorization, or user identity to
the UDP 5-tuple. Use the authenticated QUIC connection and application protocol
state. Operators still need routing that can deliver packets for a rebinding or
migration candidate to the same service instance or to infrastructure that can
route by connection ID.

The public API does not expose a general migration-control surface. Diagnostics
and qlog output are the supported troubleshooting surfaces.

Relevant SpecTrace items: `REQ-QUIC-RFC9308-S9-0001`,
`REQ-QUIC-RFC9312-S3-0002`.

## Endpoint Discovery, Versions, And Fallback

This implementation does not provide automatic fallback to TCP or endpoint
discovery through Alt-Svc, SVCB, or HTTPS records. Applications and deployments
own fallback policy and must not silently downgrade confidentiality or integrity
when falling back to another transport.

Version negotiation and compatible-version behavior are implemented in their own
RFC slices. Deploying a new QUIC version still needs an operator rollout plan,
peer compatibility testing, fallback behavior, and diagnostics.

Relevant SpecTrace item: `REQ-QUIC-RFC9308-S13-0001`.

## Application Error Handling

Separate transport failures from application protocol failures:

- Transport errors indicate QUIC protocol problems and generally affect the
  whole connection.
- Application connection errors indicate protocol-level failure for the entire
  application session.
- Application stream errors indicate cancellation or failure for one stream or
  direction.

When designing a new application mapping, define which failures close one stream
and which failures close the whole connection. Include tests that prove the
chosen error code is observable at the right layer.

## Current Applicability Summary

| Topic | Current guidance |
| --- | --- |
| Fallback | Application/deployment owned; no automatic TCP fallback |
| 0-RTT | Public application 0-RTT unavailable until a replay-safe profile exists |
| Keep-alive | Use only when continued communication is likely |
| Streams | Use for ordered reliable byte streams; mapping is application owned |
| Datagrams | RFC 9221 transport floor only; higher layers deferred |
| Priority | Local scheduling hint only |
| Flow control | Treat blocking as backpressure and keep reading |
| Stream limits | Use capacity callbacks; avoid stream-open dependency cycles |
| Error codes | Keep application and transport code spaces separate |
| Migration | Candidate paths require validation before promotion |
| Connection IDs | Do not claim broader timing-linkability mitigation |
| DSCP/QoS | No public DSCP API |
| New versions | Mechanism exists separately from deployment policy |

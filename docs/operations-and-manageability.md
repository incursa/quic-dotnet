# Operations And Manageability

This guide is for operators deploying services that use `Incursa.Quic` and for
maintainers debugging network behavior. It applies the informational guidance in
RFC 9312 to the current diagnostics surface without changing the QUIC wire
image.

Trace sources:

- [`SPEC-QUIC-RFC9312`](../specs/requirements/quic/SPEC-QUIC-RFC9312.json)
- [`RFC 9312 classification`](design/rfc9308-rfc9312-spectrace-classification.md)
- [`RFC 9312 diagnostics design note`](design/rfc9312-manageability-diagnostics.md)
- [RFC 9312 text](https://www.rfc-editor.org/rfc/rfc9312.html)

## QUIC Over UDP

QUIC runs over UDP. A deployment needs UDP reachability between clients and
servers, including firewall, NAT, load balancer, and security-group policy.
Blocked UDP usually appears as handshake timeout, missing inbound datagrams, or
socket receive/send errors rather than as a clean protocol error.

This implementation does not provide automatic TCP fallback. Applications that
need fallback must implement it above the QUIC stack and must not silently
downgrade security properties.

## UDP Blocking And Fallback Expectations

When UDP is blocked, expect one of these shapes:

- No server datagrams are observed after the client Initial.
- The server never observes a client Initial.
- Socket send or receive errors are reported by the host.
- Packet capture shows one direction passing and the reverse direction missing.

Fallback is an application or deployment decision. It should preserve
confidentiality, integrity, ALPN expectations, and application semantics.

## NAT Rebinding And Migration

The runtime can classify an address change, create a candidate path, validate
that path, and promote it after validation succeeds. Operators should expect
these safe diagnostic events during a successful rebinding or migration:

- `quic:address_change_classified`
- `quic:path_validation_challenge_sent`
- `quic:path_validation_succeeded`
- `quic:path_promoted`

Failed validation can produce `quic:path_validation_failed` or
`quic:path_validation_timed_out`. A candidate path is not the active path until a
promotion event appears.

Relevant SpecTrace item: `REQ-QUIC-RFC9312-S3-0002`.

## Load Balancer Considerations

Routing only by the UDP 5-tuple can break migration and NAT rebinding. Routing
by connection ID can help, but the raw connection ID value is not logged by
default and connection IDs can rotate after the handshake.

This repository does not implement QUIC-LB, server redirection by Retry, or a
load-balancer cooperation protocol in this slice. Deployments that require
connection ID based routing need their own load-balancer design and
compatibility testing.

## Connection ID Behavior

Connection ID issuance, retirement, and first path use are observable through
safe metadata events:

- `quic:connection_id_issued`
- `quic:connection_id_retired`
- `quic:connection_id_used_on_path`

These events use sequence numbers and path metadata. They do not log raw
connection ID bytes or stateless reset tokens.

Relevant SpecTrace item: `REQ-QUIC-RFC9312-S3-0001`.

## Retry And Version Negotiation Visibility

Retry and Version Negotiation packets use visible long-header wire-image
information. The qlog adapter can record safe packet-level metadata for these
packets, but it must not log token bytes, Retry integrity tags, protected
payload bytes, TLS keys, or decrypted application data.

Use these signals when debugging handshake deployment issues:

- packet sent/received qlog events for Initial, Handshake, Retry, and Version
  Negotiation packets
- `quic:packet_header_observed`
- `quic:coalesced_datagram_received`

Relevant SpecTrace items: `REQ-QUIC-RFC9312-S2-0001`,
`REQ-QUIC-RFC9312-S2-0002`.

## PMTU And ICMP

QUIC Initial datagrams need to meet the transport minimum datagram-size
requirements owned by RFC 9000. Later packet sizing depends on path MTU
behavior, PMTU discovery, and whether ICMP Packet Too Big signals are delivered
and accepted.

Useful diagnostics:

- `quic:pmtu_updated`
- `quic:icmp_packet_too_big_received`

An ICMP event can be rejected when the quoted packet or size fails safety checks.
Do not assume every ICMP message changes the active path maximum datagram size.

Relevant SpecTrace item: `REQ-QUIC-RFC9312-S4-0001`.

## qlog And Packet Capture Workflow

Use qlog for endpoint-side transport state and packet metadata. Use packet
capture for on-path visibility. The two are complementary:

- qlog can show connection state, path validation, packet type, close state,
  PMTU, ICMP handling, socket errors, and anti-amplification blocking.
- packet capture can show UDP reachability, packet sizes, visible long-header
  fields, Retry and Version Negotiation, and whether traffic leaves or reaches
  a host.

For qlog collection, use `QuicQlogDiagnosticsSink` with a focused capture window.
For packet capture, collect from the relevant client, server, or load-balancer
interface and record the time window so it can be correlated with qlog.

TLS key logging is separate opt-in debug behavior. Do not enable key logging in
production unless the operational procedure explicitly permits it and protects
the resulting secrets.

## What Can Be Observed On The Wire

Typically visible to a passive observer:

- UDP source and destination address and port
- packet size and timing
- long header form and packet type
- QUIC version in long headers
- destination and source connection ID fields carried on the wire
- Retry and Version Negotiation packets
- spin bit state when both endpoints participate

Not visible to a passive observer:

- decrypted application data
- most QUIC frames after packet protection
- TLS secrets
- short-header packet numbers
- application stream contents and stream IDs inside protected packets
- QPACK field sections and HTTP/3 request data after encryption
- a reliable network-visible end-of-flow signal

This repository does not implement a QUIC loss bit. Loss-bit manageability
guidance is therefore not applicable to the current runtime.

## Safe Production Logging Defaults

Transport diagnostics are disabled unless a caller supplies an enabled
diagnostics sink. The RFC 9312 diagnostics added in this repository use scalar
metadata only and avoid application data, protected payload bytes, TLS keys,
tokens, Retry integrity tags, raw connection ID bytes, and stateless reset
tokens.

Use packet-level diagnostics only for targeted troubleshooting because they can
be high volume even when they are metadata-only.

## Operational Readiness Checklist

- UDP is allowed in both directions on the selected ports.
- Load balancers route connection IDs consistently for the supported deployment
  shape.
- NAT and firewall idle timeouts are compatible with application idle behavior
  or keep-alive policy.
- qlog can be enabled for a narrow capture window.
- Packet capture can be collected at the relevant network point.
- PMTU black-hole and ICMP Packet Too Big behavior can be tested.
- Retry and Version Negotiation behavior is visible in qlog or capture.
- Operators understand that no automatic TCP fallback, QUIC-LB, DSCP control,
  loss bit, or broad passive loss measurement is provided by this slice.

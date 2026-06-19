---
title: "Troubleshooting QUIC"
---

# Troubleshooting QUIC

This guide gives maintainers and operators a starting point for diagnosing
common QUIC, HTTP/3, and QPACK failures in this repository. It emphasizes safe
diagnostics: do not collect decrypted application data, TLS keys, tokens, raw
connection IDs, or stateless reset tokens unless a documented debug procedure
explicitly requires and protects them.

Related guidance:

- [`Application protocol guidance`](application-protocol-guidance.md)
- [`Operations and manageability`](operations-and-manageability.md)
- [`SPEC-QUIC-RFC9308`](../specs/requirements/quic/SPEC-QUIC-RFC9308.json)
- [`SPEC-QUIC-RFC9312`](../specs/requirements/quic/SPEC-QUIC-RFC9312.json)

## Minimum Capture Bundle

For an issue that needs maintainer help, collect:

- qlog output from the affected endpoint with a narrow time window
- packet capture from the client, server, or load balancer when available
- endpoint role, QUIC version, ALPN, port, and whether DATAGRAM is enabled
- exact failure time and timeout values
- socket receive/send errors
- whether Retry, Version Negotiation, NAT rebinding, migration, or PMTU probing
  was expected
- interop runner stdout, stderr, qlog, key-log path, and preserved artifacts
  when the issue comes from the interop harness

Do not attach TLS key logs or decrypted captures to a general issue unless the
debug procedure explicitly permits it.

## Handshake Failure

Common causes:

- UDP is blocked in one or both directions.
- Initial datagrams do not satisfy QUIC minimum datagram-size behavior.
- Retry or Version Negotiation changes the expected flow.
- TLS certificate, SNI, ALPN, or transport parameter validation fails.
- Anti-amplification limits prevent the server from sending more data.
- Coalesced packet parsing or packet protection fails.

Useful evidence:

- packet sent/received qlog events for Initial, Handshake, Retry, and Version
  Negotiation packets
- `quic:packet_header_observed`
- `quic:coalesced_datagram_received`
- `quic:anti_amplification_blocked`
- socket error diagnostics
- packet capture showing whether both directions pass UDP

Relevant SpecTrace items: `REQ-QUIC-RFC9312-S2-0001`,
`REQ-QUIC-RFC9312-S2-0002`, `REQ-QUIC-RFC9312-S4-0001`.

## Anti-Amplification Failures

A server can be blocked from sending when it has not received enough bytes from
an unvalidated client address. This often appears as a handshake that starts and
then stalls before validation completes.

Check for `quic:anti_amplification_blocked`. Compare attempted send bytes,
remaining budget, and whether additional client packets arrived. Packet capture
should show whether the client Initial and any follow-up datagrams reached the
server.

Relevant SpecTrace item: `REQ-QUIC-RFC9312-S4-0001`.

## UDP Blocked

Symptoms:

- no server response to a client Initial
- server logs show no received datagrams
- client logs show repeated send attempts or timeout
- packet capture sees traffic only on one side of a firewall, NAT, or load
  balancer

Next steps:

- verify UDP security rules, firewall policy, NAT mapping, and load-balancer
  listener configuration
- test both directions from the same network path
- decide at the application layer whether fallback is allowed

RFC 9308 treats fallback as an application and deployment concern. This runtime
does not provide automatic TCP fallback.

## PMTU Black Hole

Symptoms:

- handshake succeeds but larger packets disappear
- transfer stalls after packet sizes increase
- ICMP Packet Too Big is blocked, malformed, or rejected
- smaller payloads succeed while larger payloads time out

Useful evidence:

- `quic:pmtu_updated`
- `quic:icmp_packet_too_big_received`
- packet capture with UDP datagram sizes
- loss or timeout timing around PMTU probes

An ICMP Packet Too Big event is only actionable if it passes runtime safety
checks. Rejected ICMP is useful evidence, but it does not prove the path maximum
datagram size changed.

Relevant SpecTrace item: `REQ-QUIC-RFC9312-S4-0001`.

## NAT Rebinding

Symptoms:

- the peer address or port changes during an otherwise live connection
- packets from the new tuple arrive but data does not continue immediately
- the connection recovers after path validation

Useful evidence:

- `quic:address_change_classified`
- `quic:path_validation_challenge_sent`
- `quic:path_validation_succeeded`
- `quic:path_promoted`

A rebinding candidate is not active until the promotion event appears. If
validation does not complete, inspect firewall and load-balancer routing for the
new tuple.

Relevant SpecTrace items: `REQ-QUIC-RFC9308-S9-0001`,
`REQ-QUIC-RFC9312-S3-0002`.

## Migration Failure

Symptoms:

- path validation fails or times out
- the connection remains on the old path
- traffic to the candidate path is dropped or routed to the wrong instance

Useful evidence:

- `quic:path_validation_failed`
- `quic:path_validation_timed_out`
- packet capture from both old and candidate paths
- connection ID lifecycle diagnostics

Check that the deployment can route packets for the candidate path to the
connection owner. Routing only by 5-tuple can break migration and rebinding.

Relevant SpecTrace item: `REQ-QUIC-RFC9312-S3-0002`.

## Connection ID Exhaustion Or Retirement Issues

Symptoms:

- migration or rebinding cannot be routed
- new path traffic is not associated with the expected connection
- stateless reset or close follows connection ID retirement

Useful evidence:

- `quic:connection_id_issued`
- `quic:connection_id_retired`
- `quic:connection_id_used_on_path`
- stateless reset diagnostics
- packet capture showing destination connection ID lengths and rotation points

Diagnostics intentionally avoid raw connection ID bytes and stateless reset
tokens. Use sequence numbers, path identity, and timing for correlation.

Relevant SpecTrace item: `REQ-QUIC-RFC9312-S3-0001`.

## 0-RTT Rejected

Current public application 0-RTT is unavailable by design. Treat rejected or
unavailable early application data as expected unless a future replay-safe
application profile explicitly enables it.

Applications should retry safe operations over normal 1-RTT behavior and must
not assume non-idempotent operations can be sent in early data.

Relevant SpecTrace item: `REQ-QUIC-RFC9308-S3P1-0001`.

## HTTP/3 Request Stalls

Common causes:

- stream limit exhaustion
- connection or stream flow-control blocking
- request or response stream not closed as expected
- application error code closes the stream or connection
- HTTP/3 control stream, SETTINGS, or stream mapping issue
- QPACK blocked stream or encoder/decoder stream issue

Useful evidence:

- `quic:flow_control_blocked`
- `quic:stream_limit_blocked`
- stream close or connection close diagnostics
- HTTP/3 adapter logs and h3spec or interop-runner output
- qlog packet timing around the stalled request

Relevant SpecTrace items: `REQ-QUIC-RFC9308-S4P4-0001`,
`REQ-QUIC-RFC9308-S4P5-0001`, `REQ-QUIC-RFC9308-S6-0001`.

## QPACK Blocked Streams

Symptoms:

- HTTP/3 request or response headers do not complete
- decoder waits for dynamic table state
- blocked stream count is exhausted
- encoder or decoder stream is missing, closed, or not processed

Useful evidence:

- HTTP/3 and QPACK test output
- stream mapping and control-stream state
- qlog timing around the affected HTTP/3 streams
- whether the dynamic table is being used in the scenario

QPACK behavior is owned by the RFC 9204 requirement set. Do not classify a QPACK
blocked-stream issue as an RFC 9308 or RFC 9312 coverage gap unless it exposes a
missing application guidance, diagnostic, or operational-readiness item.

## Close, Draining, And Stateless Reset

Symptoms:

- connection enters closing or draining earlier than expected
- peer reports a different close origin than the local endpoint
- stateless reset terminates the connection without application close details

Useful evidence:

- `quic:connection_close_state_changed`
- stateless reset diagnostics
- packet capture around the terminal packets
- application error code and transport error code surfaces

Application close codes remain separate from QUIC transport error codes. Reason
phrases and protected payload bytes are not safe production log fields.

Relevant SpecTrace items: `REQ-QUIC-RFC9308-S6-0001`,
`REQ-QUIC-RFC9312-S4-0001`.

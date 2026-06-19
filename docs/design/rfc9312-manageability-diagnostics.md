---
title: "RFC 9312 Manageability Diagnostics"
---

# RFC 9312 Manageability Diagnostics

RFC 9312 is informational guidance about what operators and managed networks can infer from QUIC. This implementation treats it as an observability and documentation surface, not as a reason to change the QUIC wire image.

## Safe Defaults

Transport diagnostics are disabled unless the caller supplies an enabled diagnostics sink. The added RFC 9312 events use scalar metadata only:

- packet header form, packet type, packet index, packet offset, datagram length, and coalesced packet count
- connection ID sequence numbers, not raw connection ID bytes
- path identity and path-validation state
- spin-bit state already visible on the wire
- ICMP Packet Too Big accepted status and maximum datagram size
- PMTU size updates
- connection close origin and close/draining phase
- socket error names and numeric socket error codes
- anti-amplification attempted bytes and remaining send budget

The diagnostics do not log decrypted application data, TLS keys or traffic secrets, Retry integrity tags, token bytes, raw stateless reset tokens, or protected packet payload bytes. Existing opt-in TLS key logging remains separate and must be explicitly requested by the caller.

## qlog Collection

Use `QuicQlogDiagnosticsSink` when a qlog trace is needed. The qlog adapter maps the RFC 9312 diagnostics to extension events such as:

- `quic:packet_header_observed`
- `quic:coalesced_datagram_received`
- `quic:connection_id_issued`
- `quic:connection_id_retired`
- `quic:connection_id_used_on_path`
- `quic:path_validation_challenge_sent`
- `quic:path_validation_succeeded`
- `quic:path_validation_failed`
- `quic:path_validation_timed_out`
- `quic:path_promoted`
- `quic:spin_bit_updated`
- `quic:icmp_packet_too_big_received`
- `quic:pmtu_updated`
- `quic:connection_close_state_changed`
- `quic:udp_receive_error`
- `quic:udp_send_error`
- `quic:anti_amplification_blocked`

Existing packet received/sent qlog events remain available for Initial, Handshake, Retry, and Version Negotiation diagnostics. Operators should treat packet-level qlog as higher-volume troubleshooting data and enable it only for targeted captures.

## Interpreting Events

`quic:packet_header_observed` identifies whether the transport saw a long-header or short-header packet and, where possible, the long-header packet type. It does not include packet payload bytes.

`quic:coalesced_datagram_received` indicates that one UDP datagram was split into multiple QUIC packets. This is useful when investigating handshake packet flight behavior or packet capture summaries that show one UDP receive but multiple QUIC packet processors.

Connection ID events expose local sequence numbers. They are intended to correlate issuance, retirement, and first observed path use without disclosing raw connection ID bytes or reset tokens.

Path events distinguish address-change classification from validation and promotion. A NAT rebinding or migration candidate is not the active path until validation succeeds and a path promotion event appears.

ICMP and PMTU events show whether a Packet Too Big indication was accepted and whether the active path maximum datagram size changed. A rejected ICMP event means the quoted packet or size did not match the runtime's safety checks.

Close-state events expose whether the connection entered closing or draining because of a local close, remote close, stateless reset, idle timeout, or another terminal origin. Reason phrases and application payloads are not logged.

## Not Implemented By Design

This repository does not implement a QUIC loss bit. RFC 9312 loss-bit manageability guidance is therefore not applicable to the current runtime.

The diagnostics do not provide passive RTT measurement beyond existing spin-bit state. Operators that need passive RTT estimation should use packet capture or qlog timing data and account for the limitations RFC 9312 describes.

This slice does not add DSCP, ECMP, QUIC-LB, load-balancer cooperation, or network policy controls. Those remain deployment or future-extension topics.

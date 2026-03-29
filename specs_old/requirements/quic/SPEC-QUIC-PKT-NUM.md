---
artifact_id: SPEC-QUIC-PKT-NUM
artifact_type: specification
title: QUIC Packet Numbers And Packet Number Spaces
domain: quic
capability: packet-number-and-space-model
status: draft
owner: quic-maintainers
tags:
  - quic
  - packets
  - packet-numbers
  - validation
  - state
related_artifacts:
  - SPEC-QUIC-PKT-PROT
  - VER-QUIC-PKT-NUM-0001
---

# SPEC-QUIC-PKT-NUM - QUIC Packet Numbers And Packet Number Spaces

## Purpose

This specification defines the packet-number value range, packet-number spaces, and the core Section 12 rules for packet-number progression and duplicate suppression. The intended implementation surface is the stateful packet-processing layer that tracks packet numbers for sending, receiving, and duplicate detection after packet protection has been removed.

## Scope

In scope are packet-number range limits, reduced header encoding width at the model level, packet-number-space membership, monotonic progression, reuse prohibition, exhaustion handling, and duplicate-suppression rules.

Out of scope are the concrete reduced packet-number encoding and decoding algorithms from Section 17.1, loss-recovery policy, and cryptographic details beyond the fact that packet numbers participate in protection.

## Context

Section 12.3 defines packet numbers as a stateful connection concern rather than a purely local field parser concern. Packet numbers exist in separate spaces, are not reusable, and must be checked for duplicates only after packet protection has been removed.

## REQ-QUIC-PKT-NUM-0001 Packet Number Range
A QUIC packet number MUST be represented as an integer in the inclusive range `0` to `2^62-1`.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0002 Packet Numbers Contribute To Packet Protection
The packet number MUST be treated as an input to the cryptographic nonce used for packet protection.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0003 Endpoints Maintain Separate Send And Receive Packet Numbers
Each endpoint MUST maintain separate packet-number state for sending and for receiving.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0004 Header Packet Numbers Use Reduced Encodings
When present in a long or short header, a packet number MUST be modeled as a reduced header encoding occupying 1 to 4 bytes.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0005 Version Negotiation And Retry Omit Packet Numbers
Version Negotiation packets and Retry packets MUST be treated as packet forms that do not contain a packet number.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0006 QUIC Uses Three Packet Number Spaces
QUIC MUST model packet numbers as divided into three packet number spaces: Initial, Handshake, and Application Data.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0007 Initial Packets Use The Initial Space
All Initial packets MUST be assigned to the Initial packet number space.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0008 Handshake Packets Use The Handshake Space
All Handshake packets MUST be assigned to the Handshake packet number space.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0009 Application-Data Packets Share One Space
All 0-RTT packets and all 1-RTT packets MUST be assigned to the Application Data packet number space.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0010 Packet Number Spaces Define Processing And Acknowledgment Context
A packet number space MUST be treated as the context in which a packet is processed and acknowledged.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0011 Initial Packets Are Sent And Acknowledged Only In Initial Space
Initial packets MUST be sent with Initial packet protection keys and MUST only be acknowledged in Initial packets.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0012 Handshake Packets Are Sent And Acknowledged Only In Handshake Space
Handshake packets MUST be sent at the Handshake encryption level and MUST only be acknowledged in Handshake packets.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0013 Packet Numbers Start At Zero In Each Space
Packet numbers in each packet number space MUST start at `0`.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0014 Packet Numbers Increase By At Least One
For packets sent in the same packet number space, each subsequent packet number MUST increase by at least `1`.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0015 0-RTT And 1-RTT Share A Space
0-RTT and 1-RTT packets MUST share the same packet number space.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

Notes:
- The RFC states that this simplifies loss-recovery implementation between the two packet types.

## REQ-QUIC-PKT-NUM-0016 Packet Numbers Are Not Reusable
A QUIC endpoint MUST NOT reuse a packet number within the same packet number space in a single connection.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0017 Packet Number Exhaustion Closes The Connection
If the sending packet number reaches `2^62-1`, the sender MUST close the connection without sending a `CONNECTION_CLOSE` frame or any further packets.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0018 Stateless Reset May Follow Further Packets After Exhaustion
After packet-number exhaustion closes the connection, an endpoint MAY send a Stateless Reset in response to further packets that it receives.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0019 Duplicate Suppression Uses Packet Number Space And Runs After Unprotection
A receiver MUST discard a newly unprotected packet unless it is certain that it has not already processed another packet with the same packet number from the same packet number space, and duplicate suppression MUST happen only after packet protection has been removed.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## REQ-QUIC-PKT-NUM-0020 Duplicate-Tracking State May Use A Minimum Packet Number Floor
An implementation MAY limit duplicate-tracking state by maintaining a minimum packet number below which packets are immediately dropped, but if it does so that minimum MUST account for large round-trip-time variation and path probing on slower network paths.

Trace:
- Source Refs:
  - RFC 9000 Section 12.3
- Verified By:
  - VER-QUIC-PKT-NUM-0001

## Open Questions

- The concrete reduced packet-number encoding and decoding algorithms referenced by Section 12.3 belong to the Section 17.1 packet-format slice and are not yet fully captured in the repository.

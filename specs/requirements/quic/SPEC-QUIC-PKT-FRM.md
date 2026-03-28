---
artifact_id: SPEC-QUIC-PKT-FRM
artifact_type: specification
title: QUIC Packet Payloads and Frame Containers
domain: quic
capability: packet-and-frame-container-parsing
status: draft
owner: quic-maintainers
tags:
  - quic
  - packets
  - frames
  - parsing
  - validation
  - coalescing
related_artifacts:
  - SPEC-QUIC-HDR
  - VER-QUIC-PKT-FRM-0001
---

# SPEC-QUIC-PKT-FRM - QUIC Packet Payloads and Frame Containers

## Purpose

This specification defines the packet-delimitation and frame-container rules that are visible from packet bytes after version-independent header recognition has completed. The intended implementation surface is a read-only parser that can identify packet boundaries, preserve coalesced packet boundaries, and validate generic frame containers without taking on cryptographic processing or stream-frame semantics.

## Scope

In scope are length-bounded packet delimitation for length-bearing packet forms, terminality rules for packet forms without a Length field, preservation of coalesced packet boundaries, frame-container completeness rules, frame-type decoding and validation, and recognition of packet types that contain no frames.

Out of scope are UDP socket handling, packet protection and decryption, packet-number lifecycle and stateful duplicate suppression, packet-number-space policy, frame-policy markings such as `N`, `C`, `P`, and `F`, and stream-frame-specific field grammar.

## Context

QUIC packet bytes may be assembled into coalesced datagram slices. Initial, 0-RTT, and Handshake packets use a Length field to determine the end of the packet, and that length includes the Packet Number field and the Payload field. Retry, Version Negotiation, and short-header packets do not contain a Length field. After packet protection is removed, packet payloads that carry frames are sequences of complete frames. The Frame Type field is a variable-length integer and defined frame types must use the shortest possible encoding.

This specification deliberately stops before stream-frame internals. Those semantics will be handled by a later slice once the repository is ready to parse stream payload contents.

## REQ-QUIC-PKT-FRM-0001 Length-Bounded Packet Delimitation
The parser MUST use the Length field on an Initial, 0-RTT, or Handshake packet to determine the end of the packet, and MUST treat that length as covering both the Packet Number field and the Payload field.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- The Length field is the boundary signal for the packet forms that carry it.
- This requirement does not apply to Retry, Version Negotiation, or short-header packets.

## REQ-QUIC-PKT-FRM-0002 Non-Length Packet Forms Are Terminal
The parser MUST represent Retry, Version Negotiation, and short-header packets as packet forms without a Length field, and MUST treat those forms as terminal within a coalesced datagram slice.

Trace:
- Source Refs:
  - RFC 9000 Sections 12.2 and 12.4.1
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- A terminal packet form cannot be followed by another packet in the same datagram slice under this specification.

## REQ-QUIC-PKT-FRM-0003 Coalesced Packet Independence
The parser MUST preserve each packet in a coalesced datagram as a separate, complete packet view and MUST not merge bytes from one packet into another.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- Packet boundaries remain independent even when multiple packets appear in one datagram slice.

## REQ-QUIC-PKT-FRM-0004 Frame-Bearing Payload Contains At Least One Frame
The parser MUST require the payload of a packet that carries frames to contain at least one complete frame.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4.3
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- A packet payload that contains no complete frame is malformed for this specification slice.

## REQ-QUIC-PKT-FRM-0005 Frame Payloads Are Complete and Packet-Bounded
The parser MUST treat frames as complete units that fit within a single packet payload slice, and MUST reject any frame that is truncated or that extends beyond the end of that slice.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4.3
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- A frame may not span multiple packets.

## REQ-QUIC-PKT-FRM-0006 Frame Type Uses Variable-Length Integer Encoding
The parser MUST decode the Frame Type field as a variable-length integer.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- The frame grammar begins with a Frame Type field, followed by type-dependent fields.

## REQ-QUIC-PKT-FRM-0007 Frame Type Uses Shortest Possible Encoding
The parser MUST require a recognized Frame Type value to use the shortest possible variable-length integer encoding.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4.18
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- For the frame types defined by this specification slice, the shortest encoding is a single byte.
- A longer-than-necessary encoding is malformed for this specification slice even if it could represent the same numeric value.

## REQ-QUIC-PKT-FRM-0008 Unknown Frame Types Are Rejected
The parser MUST reject a frame whose Frame Type value is not recognized by the implementation.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4.16
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- Unknown frame types are not interpreted generically.

## REQ-QUIC-PKT-FRM-0009 No-Frame Packet Types
The parser MUST represent Version Negotiation, Retry, and Stateless Reset packets as packet types that contain no frames.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4.1
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- This requirement applies to packet-type classification only; it does not define packet-number-space policy or cryptographic processing.

## Open Questions

- None for this slice. Packet-number-space lifecycle, packet-number reuse, duplicate suppression, frame-policy annotations `N`, `C`, `P`, and `F`, and stream-frame field grammar are intentionally deferred to later stateful or stream-specific specs.

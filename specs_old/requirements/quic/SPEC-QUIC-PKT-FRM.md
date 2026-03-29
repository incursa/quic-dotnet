---
artifact_id: SPEC-QUIC-PKT-FRM
artifact_type: specification
title: QUIC Datagram Coalescing and Generic Frame Rules
domain: quic
capability: packet-coalescing-and-frame-validation
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
  - SPEC-QUIC-VINT
  - SPEC-QUIC-PKT-NUM
  - VER-QUIC-PKT-FRM-0001
---

# SPEC-QUIC-PKT-FRM - QUIC Datagram Coalescing and Generic Frame Rules

## Purpose

This specification defines the QUIC rules for coalescing multiple packets into one UDP datagram and for interpreting a decrypted packet payload as a sequence of generic frames. The intended implementation surface is a datagram and frame parser that preserves packet boundaries, enforces packet and frame placement rules, and rejects malformed or disallowed frame containers before frame-specific bodies are interpreted.

## Scope

In scope are Length-field-based datagram slicing, coalesced-packet independence, terminal packet forms, generic frame-container rules, frame-type encoding rules, frame-placement constraints, and the generic `Pkts` and `Spec` policy markings summarized in RFC 9000 Section 12.

Out of scope are UDP socket APIs, the concrete byte layout of packet-specific headers from Section 17, concrete frame-body parsing beyond STREAM, cryptographic algorithms from QUIC-TLS, and loss-recovery behavior beyond the generic packet and frame placement rules captured here.

## Context

QUIC allows multiple packets to be coalesced into a single UDP datagram when the packet form carries an explicit Length field. After packet protection is removed, a frame-bearing packet payload is a sequence of complete frames. Section 12 also imposes packet-placement and packet-number-space rules on frames, including generic handling for unknown frame types and overlong frame-type encodings.

## REQ-QUIC-PKT-FRM-0001 Length-Carrying Packet Forms
Initial, 0-RTT, and Handshake packets MUST be treated as packet forms that carry a Length field for packet delimitation.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0002 Length Determines Packet End
The parser MUST use the Length field on an Initial, 0-RTT, or Handshake packet to determine the end of that packet inside a UDP datagram.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0003 Length Covers Packet Number And Payload
The parser MUST treat the Length field on an Initial, 0-RTT, or Handshake packet as covering both the Packet Number field and the Payload field.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0004 Payload Boundary Is Final After Header Protection Removal
The parser MUST treat the payload length inside a length-bearing packet as fully known only after header protection has been removed.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0005 Sender-Side Packet Coalescing Is Permitted
An endpoint MAY coalesce multiple QUIC packets into a single UDP datagram when packet boundaries can be determined from the encoded packet forms.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- The RFC cites handshake efficiency and PMTU probing as reasons to do this.

## REQ-QUIC-PKT-FRM-0006 Receivers Process Coalesced Packets
A receiver MUST be able to process coalesced QUIC packets carried in a single UDP datagram.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0007 Short-Header Packets Are Terminal In A Datagram
A packet with a short header MUST be treated as terminal within a UDP datagram because it does not include a Length field.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0008 Same-Level Data Prefers Frames Over Same-Level Coalescing
An endpoint SHOULD include multiple frames in a single packet when those frames are sent at the same encryption level, rather than coalescing multiple packets at that same encryption level.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0009 Routing May Use First Packet Metadata
A receiver MAY route a UDP datagram based on the information in the first packet contained in that datagram.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0010 Coalesced Packets Must Share Connection Identity
A sender MUST NOT coalesce QUIC packets with different connection IDs into a single UDP datagram.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0011 Subsequent Different Destination Connection IDs Should Be Ignored
A receiver SHOULD ignore any packet after the first packet in a UDP datagram when that later packet has a different Destination Connection ID from the first packet.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0012 Coalesced Packets Remain Separate And Complete
Every QUIC packet that is coalesced into a single UDP datagram MUST be treated as a separate and complete packet.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0013 Coalesced Packets Are Processed Individually
A receiver MUST process each QUIC packet in a coalesced UDP datagram individually.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0014 Coalesced Packets Are Acknowledged Individually
A receiver MUST acknowledge each QUIC packet in a coalesced UDP datagram separately, as though the packets had arrived in separate UDP datagrams.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0015 One Failed Packet Does Not Stop The Rest
If processing of one coalesced packet fails because keys are unavailable or for any other reason, the receiver MAY discard or buffer that packet for later processing and MUST still attempt to process the remaining packets.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0016 Retry Version-Negotiation And Short-Header Packets Are Terminal
Retry packets, Version Negotiation packets, and short-header packets MUST be treated as packet forms that cannot be followed by another QUIC packet in the same UDP datagram.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0017 Retry And Version Negotiation Are Never Coalesced
An endpoint MUST NOT coalesce a Retry packet or a Version Negotiation packet with any other QUIC packet.

Trace:
- Source Refs:
  - RFC 9000 Section 12.2
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0018 Decrypted Frame-Bearing Payload Is A Frame Sequence
After packet protection is removed, the payload of a QUIC packet that carries frames MUST be interpreted as a sequence of complete frames.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0019 Certain Packet Types Carry No Frames
Version Negotiation, Stateless Reset, and Retry packets MUST be treated as packet types that contain no frames.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0020 Frame-Bearing Payload Contains At Least One Frame
The payload of a packet that contains frames MUST contain at least one complete frame and MAY contain multiple frames of one or more frame types.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0021 Empty Frame-Bearing Payload Is A Protocol Violation
An endpoint MUST treat receipt of a packet that is required to contain frames but contains no frames as a connection error of type `PROTOCOL_VIOLATION`.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0022 Frames Are Packet-Bounded
Frames MUST fit entirely within a single QUIC packet and MUST NOT span multiple packets.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0023 Generic Frame Layout
The parser MUST treat each frame as beginning with a Frame Type field followed by type-dependent fields.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0024 Certain Frame Families Carry Flags In The Frame Type
The parser MUST treat the Frame Type field in ACK, STREAM, MAX_STREAMS, STREAMS_BLOCKED, and CONNECTION_CLOSE frames as carrying additional frame-specific flags in addition to the frame identity.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0025 Other Frame Families Use Frame Type Only As An Identifier
For frame types other than ACK, STREAM, MAX_STREAMS, STREAMS_BLOCKED, and CONNECTION_CLOSE, the parser MUST treat the Frame Type field as identifying the frame type only.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0026 Frame Placement Rules Must Be Enforced
An endpoint MUST treat receipt of a frame in a packet type that is not permitted for that frame as a connection error of type `PROTOCOL_VIOLATION`.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
  - RFC 9000 Section 12.5
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0027 N-Marked Packets Are Not Ack-Eliciting
Packets that contain only frames marked `N` in the generic Section 12 frame summary MUST be treated as not ack-eliciting.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0028 C-Marked Packets Do Not Count Toward Bytes In Flight
Packets that contain only frames marked `C` in the generic Section 12 frame summary MUST be treated as not contributing to bytes in flight for congestion-control accounting.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0029 P-Marked Packets Can Probe New Paths
Packets that contain only frames marked `P` in the generic Section 12 frame summary MUST be treated as eligible to probe a new network path during connection migration.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0030 F-Marked Frame Contents Are Flow Controlled
Frame contents marked `F` in the generic Section 12 frame summary MUST be treated as flow controlled.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0031 Unknown Frame Types Are Frame-Encoding Errors
An endpoint MUST treat receipt of a frame with an unknown frame type as a connection error of type `FRAME_ENCODING_ERROR`.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0032 Frames Are Idempotent
All valid frames in this version of QUIC MUST be treated as idempotent, such that receiving the same valid frame more than once does not create undesirable side effects or errors.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0033 Frame Type Uses Variable-Length Integer Encoding
The parser MUST decode the Frame Type field as a QUIC variable-length integer.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
  - RFC 9000 Section 16
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0034 Frame Type Uses The Shortest Possible Encoding
The parser MUST require a recognized frame type to use the shortest possible variable-length integer encoding.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

Notes:
- For the frame types defined in RFC 9000, this means a single-byte encoding.

## REQ-QUIC-PKT-FRM-0035 Overlong Frame-Type Encodings May Be Protocol Violations
An endpoint MAY treat receipt of a frame type that uses a longer encoding than necessary as a connection error of type `PROTOCOL_VIOLATION`.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0036 PADDING PING And CRYPTO May Appear In Any Packet Number Space
PADDING, PING, and CRYPTO frames MAY appear in any packet number space.

Trace:
- Source Refs:
  - RFC 9000 Section 12.5
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0037 QUIC-Layer Connection-Close May Appear In Any Packet Number Space
A CONNECTION_CLOSE frame of type `0x1c` signaling a QUIC-layer error MAY appear in any packet number space.

Trace:
- Source Refs:
  - RFC 9000 Section 12.5
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0038 Application-Error Connection-Close Is Application-Data Only
A CONNECTION_CLOSE frame of type `0x1d` signaling an application error MUST only appear in the application-data packet number space.

Trace:
- Source Refs:
  - RFC 9000 Section 12.5
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0039 ACK Placement And Acknowledgment Scope
ACK frames MAY appear in any packet number space, but an ACK frame MUST acknowledge only packets from the same packet number space in which that ACK frame appears.

Trace:
- Source Refs:
  - RFC 9000 Section 12.5
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0040 ACK Frames Are Forbidden In 0-RTT Packets
An endpoint MUST NOT send an ACK frame in a 0-RTT packet.

Trace:
- Source Refs:
  - RFC 9000 Section 12.5
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0041 Non-Exception Frames Are Application-Data Only
Frame types other than PADDING, PING, CRYPTO, CONNECTION_CLOSE type `0x1c`, CONNECTION_CLOSE type `0x1d`, and ACK MUST only be sent in the application-data packet number space.

Trace:
- Source Refs:
  - RFC 9000 Section 12.5
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0042 Certain Frames In 0-RTT May Be Treated As Protocol Violations
A server MAY treat receipt in a 0-RTT packet of any of the following frame types as a connection error of type `PROTOCOL_VIOLATION`: ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, or RETIRE_CONNECTION_ID.

Trace:
- Source Refs:
  - RFC 9000 Section 12.5
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0043 All Frames May Appear In 1-RTT Packets
All frame types defined for this version of QUIC MAY appear in 1-RTT packets.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## REQ-QUIC-PKT-FRM-0044 Section-12 Frame Summary Metadata Is Not The IANA Registry
The `Pkts` and `Spec` columns in the generic Section 12 frame summary MUST be treated as descriptive specification metadata and MUST NOT be treated as part of the IANA frame-type registry.

Trace:
- Source Refs:
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-PKT-FRM-0001

## Open Questions

- The exact byte locations of Length and Packet Number fields for Initial, 0-RTT, Handshake, Retry, and 1-RTT packets depend on the Section 17 packet-form specifications that have not yet been fully captured in this repository.
- Concrete frame-body semantics outside STREAM still need their own frame-specific requirement slices under Section 19.

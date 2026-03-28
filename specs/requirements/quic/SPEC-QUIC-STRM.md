---
artifact_id: SPEC-QUIC-STRM
artifact_type: specification
title: QUIC Stream Identifiers and STREAM Frames
domain: quic
capability: stream-identifier-and-frame-parsing
status: draft
owner: quic-maintainers
tags:
  - quic
  - streams
  - frames
  - parsing
  - validation
related_artifacts:
  - SPEC-QUIC-VINT
  - SPEC-QUIC-PKT-FRM
  - VER-QUIC-STRM-0001
---

# SPEC-QUIC-STRM - QUIC Stream Identifiers and STREAM Frames

## Purpose

This specification defines the byte-visible structure of QUIC stream identifiers and STREAM frames. The intended implementation surface is a parser that can classify a stream identifier from its encoded value, identify STREAM frame field presence from the frame type bits, and expose the parsed byte ranges without conflating them with later stream-state policy.

## Scope

In scope are stream identifier encoding and classification, the STREAM frame type range, the OFF/LEN/FIN bit behavior, and the byte layout of the STREAM frame fields.

Out of scope are stream identifier reuse, out-of-order stream opening, stream-creation policy, `STREAM_STATE_ERROR` handling, and flow-control enforcement or error-class selection for oversized stream offsets.

## Context

Stream identifiers are variable-length integers with additional meaning in their low-order bits. STREAM frames use a fixed type range of `0x08` through `0x0f`, where the low-order bits determine which optional fields are present. When the LEN bit is clear, the Stream Data field consumes the rest of the packet. The STREAM frame grammar is therefore a mix of a type discriminator and a varint-backed field layout.

This specification is intentionally narrower than full stream management. It captures the byte-level meaning that is visible to a parser while leaving stream lifecycle and flow-control semantics to later stateful processing.

## REQ-QUIC-STRM-0001 Stream Identifier Encoding
The parser MUST represent a QUIC stream identifier as a variable-length integer in the inclusive range `0` to `2^62-1`.

Trace:
- Source Refs:
  - RFC 9000 Section 2.1
  - RFC 9000 Section 19.8
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- Stream identifiers use the QUIC variable-length integer encoding defined in [`SPEC-QUIC-VINT`](./SPEC-QUIC-VINT.md).

## REQ-QUIC-STRM-0002 Stream Initiator Bit
The parser MUST classify the least significant bit of a stream identifier as the initiator bit, with even-numbered stream identifiers identifying client-initiated streams and odd-numbered stream identifiers identifying server-initiated streams.

Trace:
- Source Refs:
  - RFC 9000 Section 2.1
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- This requirement captures the initiator side of the stream-type classification.

## REQ-QUIC-STRM-0003 Stream Direction Bit
The parser MUST classify the second least significant bit of a stream identifier as the direction bit, with a cleared bit identifying a bidirectional stream and a set bit identifying a unidirectional stream.

Trace:
- Source Refs:
  - RFC 9000 Section 2.1
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- This requirement captures the bidirectional versus unidirectional distinction.

## REQ-QUIC-STRM-0004 Stream Type Classification
The parser MUST classify a stream identifier by its two least significant bits into one of the four QUIC stream types: client-initiated bidirectional, server-initiated bidirectional, client-initiated unidirectional, or server-initiated unidirectional.

Trace:
- Source Refs:
  - RFC 9000 Section 2.1
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- The four type values are `0x00`, `0x01`, `0x02`, and `0x03`.

## REQ-QUIC-STRM-0005 STREAM Frame Type Range
The parser MUST recognize STREAM frames by a frame type value in the inclusive range `0x08` through `0x0f`.

Trace:
- Source Refs:
  - RFC 9000 Section 19.8
  - RFC 9000 Section 12.4
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- STREAM frame types encode additional flags in the three low-order bits.

## REQ-QUIC-STRM-0006 STREAM Frame Layout
The parser MUST represent a STREAM frame as a type field, a stream identifier, optional offset and length fields, and a Stream Data field.

Trace:
- Source Refs:
  - RFC 9000 Section 19.8
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- The frame grammar is `Type (i)`, `Stream ID (i)`, optional `Offset (i)`, optional `Length (i)`, and `Stream Data (..)`.

## REQ-QUIC-STRM-0007 Offset Presence Bit
The parser MUST treat the OFF bit in a STREAM frame type as the presence indicator for the Offset field, and MUST use an offset of `0` when the OFF bit is clear.

Trace:
- Source Refs:
  - RFC 9000 Section 19.8
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- A set OFF bit means the Offset field is present.

## REQ-QUIC-STRM-0008 Length Presence Bit
The parser MUST treat the LEN bit in a STREAM frame type as the presence indicator for the Length field, and MUST treat the Stream Data field as extending to the end of the packet when the LEN bit is clear.

Trace:
- Source Refs:
  - RFC 9000 Section 19.8
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- A set LEN bit means the Length field is present.

## REQ-QUIC-STRM-0009 FIN Bit
The parser MUST treat the FIN bit in a STREAM frame type as an end-of-stream indicator, and MUST expose the final size of the stream as the sum of the offset and the length of the frame data.

Trace:
- Source Refs:
  - RFC 9000 Section 19.8
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- The FIN bit does not change the byte layout of the frame.

## REQ-QUIC-STRM-0010 Zero-Length Stream Data Offset Semantics
The parser MUST preserve the offset of a STREAM frame whose Stream Data length is zero as the offset of the next byte that would be sent.

Trace:
- Source Refs:
  - RFC 9000 Section 19.8
- Verified By:
  - VER-QUIC-STRM-0001

Notes:
- This is a byte-visible semantic rule for zero-length STREAM data.

## Open Questions

- None for this slice. Stream identifier reuse, out-of-order opening, `STREAM_STATE_ERROR` handling, and flow-control enforcement are intentionally deferred to later stateful stream-management specs.

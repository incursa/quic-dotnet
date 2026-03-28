---
artifact_id: SPEC-QUIC-VINT
artifact_type: specification
title: QUIC Variable-Length Integers
domain: quic
capability: variable-length-integer-parsing
status: draft
owner: quic-maintainers
tags:
  - quic
  - integers
  - parsing
  - encoding
related_artifacts:
  - SPEC-QUIC-PKT-FRM
  - SPEC-QUIC-STRM
  - VER-QUIC-VINT-0001
---

# SPEC-QUIC-VINT - QUIC Variable-Length Integers

## Purpose

This specification defines the reusable variable-length integer encoding used by QUIC fields that are explicitly documented as varints. The intended implementation surface is a byte-oriented reader and writer that can decode the encoded length, preserve the value range, and fail fast on truncated input.

## Scope

In scope are the four QUIC variable-length integer encodings, the value range they can represent, the network-byte-order interpretation of the encoded bits, and the requirement to reject truncated inputs.

Out of scope are field-specific policies that sit on top of the encoding, such as the frame-type shortest-encoding rule, the fixed-width integer fields used by packet headers, and any stream or packet-state semantics that consume a decoded value.

## Context

QUIC encodes certain non-negative integers as 1, 2, 4, or 8-byte values. The two most significant bits of the first byte select the encoded length, and the remaining bits carry the integer value in network byte order. Most fields that use this encoding may use any valid encoded length that can represent the value, even when a shorter encoding would be possible.

This specification exists so that packet, frame, and stream parsers can share a single primitive for variable-length integer decoding and validation.

## REQ-QUIC-VINT-0001 Encoded Length Selection
The parser MUST determine the encoded length of a QUIC variable-length integer from the two most significant bits of the first byte and MUST recognize 1-byte, 2-byte, 4-byte, and 8-byte encodings.

Trace:
- Source Refs:
  - RFC 9000 Section 16
- Verified By:
  - VER-QUIC-VINT-0001

Notes:
- The encoded length values are 1, 2, 4, and 8 bytes.
- The length selector is not itself part of the decoded integer value.

## REQ-QUIC-VINT-0002 Network-Byte-Order Value Decoding
The parser MUST decode the integer value from the remaining bits of the encoded bytes in network byte order.

Trace:
- Source Refs:
  - RFC 9000 Section 16
- Verified By:
  - VER-QUIC-VINT-0001

Notes:
- The value bits follow the length selector bits in the first byte and continue through the remaining bytes of the chosen encoding length.

## REQ-QUIC-VINT-0003 Value Range
The parser MUST represent decoded QUIC variable-length integer values in the inclusive range `0` to `2^62-1`.

Trace:
- Source Refs:
  - RFC 9000 Section 16
- Verified By:
  - VER-QUIC-VINT-0001

Notes:
- The four encodings correspond to 6-bit, 14-bit, 30-bit, and 62-bit value ranges.
- Values outside that range are not representable by this encoding.

## REQ-QUIC-VINT-0004 Truncation Rejection
The parser MUST reject a QUIC variable-length integer when the input ends before all bytes required by the encoded length are available.

Trace:
- Source Refs:
  - RFC 9000 Section 16
- Verified By:
  - VER-QUIC-VINT-0001

Notes:
- This is a fail-fast validation rule for malformed or truncated inputs.

## REQ-QUIC-VINT-0005 Non-Minimal Encodings Are Permitted
The parser MUST accept non-minimal QUIC variable-length integer encodings when the consuming field does not impose a shortest-encoding rule.

Trace:
- Source Refs:
  - RFC 9000 Section 16
- Verified By:
  - VER-QUIC-VINT-0001

Notes:
- This requirement captures the default QUIC behavior for varint-backed fields.
- The frame-type field is the special case that imposes a shortest-encoding rule in a separate specification slice.

## Open Questions

- None for this slice. Field-specific shortest-encoding or fixed-width rules are handled by the consuming specification that names the field.

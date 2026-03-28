---
artifact_id: SPEC-QUIC-HDR
artifact_type: specification
title: Version-Independent QUIC Packet Headers
domain: quic
capability: packet-header-parsing
status: draft
owner: quic-maintainers
tags:
  - quic
  - headers
  - parsing
  - validation
  - version-negotiation
related_artifacts:
  - VER-QUIC-HDR-0001
---

# SPEC-QUIC-HDR - Version-Independent QUIC Packet Headers

## Purpose

This specification defines the version-independent QUIC packet header forms that the repository recognizes from a byte span, along with the validation rules that run before any version-specific processing. The intended implementation surface is a read-only parse model that fails fast on malformed input.

## Scope

In scope are header-form discrimination, long-header fixed fields, connection ID validation where the length is encoded, version field handling, and Version Negotiation packet validation.

Out of scope are UDP datagram handling, packet protection, decryption, payload semantics after the header, and any version-specific interpretation that is not directly encoded in the version-independent packet shape.

## Context

QUIC packet headers are classified by the most significant bit of the first byte. Long headers encode an explicit version and explicit connection ID lengths. Short headers do not encode a version field or encoded connection ID lengths. Version Negotiation packets are long-header-form packets whose version field is zero and whose trailing bytes list supported versions.

## REQ-QUIC-HDR-0001 Header Form Classification
The parser MUST classify a packet as long-header-form when the most significant bit of the first byte is set and as short-header-form when that bit is cleared.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- This classification is independent of the packet body, connection IDs, and version-specific semantics.

## REQ-QUIC-HDR-0002 First-Byte Control Bits
The parser MUST preserve the seven non-form bits of the first byte as raw header-control bits associated with the parsed packet.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- For long-header and short-header packets, those bits are version-specific.
- For Version Negotiation packets, those bits are unused on receipt and are not part of the version-independent validation outcome.

## REQ-QUIC-HDR-0003 Long Header Layout
The parser MUST require a long-header-form packet to contain a 32-bit Version field, an 8-bit Destination Connection ID Length field, the Destination Connection ID bytes indicated by that length, an 8-bit Source Connection ID Length field, the Source Connection ID bytes indicated by that length, and version-specific trailing data.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- The length fields are byte counts, so each connection ID is constrained to 0 through 255 bytes by the encoded length.
- The trailing bytes remain version-specific data and are not interpreted by this specification.

## REQ-QUIC-HDR-0004 Long Header Truncation
The parser MUST reject a long-header-form packet when the input ends before any fixed-length field or before the number of bytes declared by either connection-ID length field are available.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- This is a fail-fast validation rule.
- The parser should not attempt to infer later fields once a required byte range is missing.

## REQ-QUIC-HDR-0005 Connection ID Opaqueness
The parser MUST treat connection IDs as opaque byte sequences and preserve the bytes exactly as encoded.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- The parser does not assign semantics to connection ID bytes.
- This requirement applies to every parsed connection ID regardless of length.

## REQ-QUIC-HDR-0006 Version Zero Reservation
The parser MUST treat a Version field value of `0x00000000` as reserved for Version Negotiation.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- Other version values are exposed as version identifiers, but support or compatibility decisions belong to later version-specific logic.

## REQ-QUIC-HDR-0007 Short Header Encoded Fields
The parser MUST classify a short-header-form packet by a cleared most significant bit and represent the version-independent result without encoded Version, Destination Connection ID Length, or Source Connection ID Length fields.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- The destination connection ID boundary in a short-header packet is version-specific and remains an open gap for the first implementation slice.

## REQ-QUIC-HDR-0008 Version Negotiation Identification
The parser MUST identify a Version Negotiation packet as a long-header-form packet whose Version field is `0x00000000`.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- Version Negotiation is a parse-time classification distinct from ordinary long-header packets that carry non-zero version values.

## REQ-QUIC-HDR-0009 Version Negotiation Unused Bits
The parser MUST ignore the seven non-form bits in the first byte of a Version Negotiation packet when determining its validity or packet type.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- Those bits are explicitly unused on receipt for this packet form.

## REQ-QUIC-HDR-0010 Supported Version Validation
The parser MUST reject a Version Negotiation packet that contains no complete Supported Version values or that terminates inside a Supported Version value.

Trace:
- Source Refs:
  - RFC 8999
- Verified By:
  - VER-QUIC-HDR-0001

Notes:
- Supported Version entries are 32-bit values, so any trailing fragment shorter than four bytes is malformed.

## Open Questions

- How should the version-independent parser represent the bytes that follow the first byte of a short-header packet when the destination connection ID length is not encoded?

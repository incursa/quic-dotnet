---
artifact_id: SPEC-QUIC-RFC8999
artifact_type: specification
title: QUIC Invariants (RFC 8999)
domain: quic
capability: version-independent-invariants
status: draft
owner: quic-maintainers
---

# [`SPEC-QUIC-RFC8999`](./SPEC-QUIC-RFC8999.md) - QUIC Invariants (RFC 8999)

## Purpose

Capture the version-independent QUIC requirements defined by RFC 8999 as canonical spec-trace clauses.

## Scope

This specification covers the normative obligations assembled from the reviewed RFC 8999 extraction outputs and preserves RFC section and sentence provenance in `Source Refs`.

## Context

RFC 8999 defines version-independent QUIC properties that overlap with RFC 9000 transport packet structure, so the assembly keeps RFC 8999 obligations intact while surfacing overlap in generated review reports.

## REQ-QUIC-RFC8999-S5P1-0001 Header Form Bit
The first bit of a QUIC long header packet MUST be set to 1.

Trace:
- Source Refs:
  - RFC 8999 §5.1 RFC8999-S5.1-B3-P0-S2
  - RFC 8999 §5.1 RFC8999-S5.1-B5-P2-S1
  - https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1

## REQ-QUIC-RFC8999-S5P1-0002 Version-Specific Bits
The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.

Trace:
- Source Refs:
  - RFC 8999 §5.1 RFC8999-S5.1-B3-P0-S3
  - RFC 8999 §5.1 RFC8999-S5.1-B5-P2-S2
  - https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1

## REQ-QUIC-RFC8999-S5P1-0003 Version Field
The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.

Trace:
- Source Refs:
  - RFC 8999 §5.1 RFC8999-S5.1-B3-P0-S4
  - RFC 8999 §5.1 RFC8999-S5.1-B6-P3-S1
  - https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1

## REQ-QUIC-RFC8999-S5P1-0004 Destination Connection ID Length Encoding
The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.

Trace:
- Source Refs:
  - RFC 8999 §5.1 RFC8999-S5.1-B3-P0-S5
  - RFC 8999 §5.1 RFC8999-S5.1-B7-P4-S1
  - RFC 8999 §5.1 RFC8999-S5.1-B7-P4-S2
  - https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1

## REQ-QUIC-RFC8999-S5P1-0005 Destination Connection ID Size
The Destination Connection ID field MUST follow its length byte and be between 0 and 255 bytes long.

Trace:
- Source Refs:
  - RFC 8999 §5.1 RFC8999-S5.1-B3-P0-S6
  - RFC 8999 §5.1 RFC8999-S5.1-B7-P4-S3
  - https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1

## REQ-QUIC-RFC8999-S5P1-0006 Source Connection ID Length Encoding
The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.

Trace:
- Source Refs:
  - RFC 8999 §5.1 RFC8999-S5.1-B3-P0-S7
  - RFC 8999 §5.1 RFC8999-S5.1-B8-P5-S1
  - RFC 8999 §5.1 RFC8999-S5.1-B8-P5-S2
  - https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1

## REQ-QUIC-RFC8999-S5P1-0007 Source Connection ID Size
The Source Connection ID field MUST follow its length byte and be between 0 and 255 bytes long.

Trace:
- Source Refs:
  - RFC 8999 §5.1 RFC8999-S5.1-B3-P0-S8
  - RFC 8999 §5.1 RFC8999-S5.1-B8-P5-S3
  - https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1

## REQ-QUIC-RFC8999-S5P1-0008 Version-Specific Remainder
The remainder of a QUIC long header packet MUST contain version-specific content.

Trace:
- Source Refs:
  - RFC 8999 §5.1 RFC8999-S5.1-B3-P0-S9
  - RFC 8999 §5.1 RFC8999-S5.1-B9-P6-S1
  - https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1

---
artifact_id: SPEC-QUIC-HDR
artifact_type: specification
title: QUIC Header Parsing
domain: quic
capability: header-parsing
status: draft
owner: quic-maintainers
tags:
  - quic
  - headers
  - parsing
  - transport
related_artifacts:
  - ARC-QUIC-HDR-0001
  - WI-QUIC-HDR-0001
  - VER-QUIC-HDR-0001
---

# [`SPEC-QUIC-HDR`](./SPEC-QUIC-HDR.md) - QUIC Header Parsing

## Purpose

Capture the header-parsing expectations that the current QUIC parser and test
suite rely on.

## Scope

This specification covers the packet-form discriminator, the minimum-length
checks for the packet headers that the parser accepts, and the traceable proof
chain for the current header slice.

## Context

The repository already carries long-header, short-header, packet-parser,
property, fuzz, and benchmark code around the header substrate. This
specification gives that surface a stable requirement home so the quality lane
can report on it consistently.

## REQ-QUIC-HDR-0001 Distinguish long and short headers
The parser MUST distinguish long and short QUIC headers from the first bit of
the first octet.

Trace:
- Satisfied By:
  - [`ARC-QUIC-HDR-0001`](../../architecture/quic/ARC-QUIC-HDR-0001.md)
- Implemented By:
  - [`WI-QUIC-HDR-0001`](../../work-items/quic/WI-QUIC-HDR-0001.md)
- Verified By:
  - [`VER-QUIC-HDR-0001`](../../verification/quic/VER-QUIC-HDR-0001.md)
- Source Refs:
  - RFC 8999 §5.1 https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
  - RFC 9000 §17 https://www.rfc-editor.org/rfc/rfc9000.html#section-17
- Test Refs:
  - [`QuicPacketParserTests.cs`](../../../tests/Incursa.Quic.Tests/QuicPacketParserTests.cs)
  - [`QuicLongHeaderPacketTests.cs`](../../../tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs)
  - [`QuicShortHeaderPacketTests.cs`](../../../tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs)
  - [`QuicHeaderPropertyTests.cs`](../../../tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs)
  - [`QuicHeaderFuzzTests.cs`](../../../tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs)
- Code Refs:
  - [`QuicPacketParser.cs`](../../../src/Incursa.Quic/QuicPacketParser.cs)
  - [`QuicLongHeaderPacket.cs`](../../../src/Incursa.Quic/QuicLongHeaderPacket.cs)
  - [`QuicShortHeaderPacket.cs`](../../../src/Incursa.Quic/QuicShortHeaderPacket.cs)
  - [`QuicHeaderForm.cs`](../../../src/Incursa.Quic/QuicHeaderForm.cs)
Notes:
- The requirement covers the parser's top-level form discrimination only.

## REQ-QUIC-HDR-0002 Reject truncated header inputs
The parser MUST reject inputs that do not contain the minimum fixed fields for
the detected header form.

Trace:
- Satisfied By:
  - [`ARC-QUIC-HDR-0001`](../../architecture/quic/ARC-QUIC-HDR-0001.md)
- Implemented By:
  - [`WI-QUIC-HDR-0001`](../../work-items/quic/WI-QUIC-HDR-0001.md)
- Verified By:
  - [`VER-QUIC-HDR-0001`](../../verification/quic/VER-QUIC-HDR-0001.md)
- Source Refs:
  - RFC 8999 §5.1 https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
  - RFC 9000 §17.2 https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
- Test Refs:
  - [`QuicPacketParserTests.cs`](../../../tests/Incursa.Quic.Tests/QuicPacketParserTests.cs)
  - [`QuicLongHeaderPacketTests.cs`](../../../tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs)
  - [`QuicShortHeaderPacketTests.cs`](../../../tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs)
  - [`QuicHeaderPropertyTests.cs`](../../../tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs)
  - [`QuicHeaderFuzzTests.cs`](../../../tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs)
- Code Refs:
  - [`QuicPacketParser.cs`](../../../src/Incursa.Quic/QuicPacketParser.cs)
  - [`QuicLongHeaderPacket.cs`](../../../src/Incursa.Quic/QuicLongHeaderPacket.cs)
  - [`QuicShortHeaderPacket.cs`](../../../src/Incursa.Quic/QuicShortHeaderPacket.cs)
  - [`QuicVariableLengthInteger.cs`](../../../src/Incursa.Quic/QuicVariableLengthInteger.cs)
Notes:
- This requirement intentionally stays narrow so the packet parser can evolve
  without changing the header contract shape.

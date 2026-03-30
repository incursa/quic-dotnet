---
artifact_id: ARC-QUIC-HDR-0001
artifact_type: architecture
title: QUIC Header Parsing Architecture
domain: quic
status: draft
owner: quic-maintainers
satisfies:
  - REQ-QUIC-HDR-0001
  - REQ-QUIC-HDR-0002
related_artifacts:
  - SPEC-QUIC-HDR
  - WI-QUIC-HDR-0001
  - VER-QUIC-HDR-0001
---

# [`ARC-QUIC-HDR-0001`](./ARC-QUIC-HDR-0001.md) - QUIC Header Parsing Architecture

## Purpose

Describe how the current header-parsing surface satisfies the QUIC header
requirements without constraining implementation details more than necessary.

## Scope

This design covers the packet-form discriminator, the packet-specific parsing
types, and the strict rejection path for truncated header inputs.

## Design

- [`QuicPacketParser`](../../../src/Incursa.Quic/QuicPacketParser.cs) acts as the top-level discriminator and validates the
  minimum input shape before delegating to packet-specific helpers.
- [`QuicLongHeaderPacket`](../../../src/Incursa.Quic/QuicLongHeaderPacket.cs) and [`QuicShortHeaderPacket`](../../../src/Incursa.Quic/QuicShortHeaderPacket.cs) hold the parsed shape for
  their respective packet forms.
- [`QuicHeaderForm`](../../../src/Incursa.Quic/QuicHeaderForm.cs) keeps the form bit interpretation explicit and readable.
- [`QuicVariableLengthInteger`](../../../src/Incursa.Quic/QuicVariableLengthInteger.cs) provides the length-encoding support required by
  the long-header substrate.

## Invariants

- The parser should not guess when the header form is ambiguous or incomplete.
- Truncated inputs should fail early and predictably.
- Packet-specific metadata should stay in the packet-specific type rather than
  in the top-level discriminator.

## Tradeoffs

- The architecture keeps the parser simple and testable at the expense of a
  slightly more explicit type split.
- The header slice remains narrow so future requirements can extend parsing
  behavior without rewriting the entire packet model.

## Trace Links

- Satisfies:
  - REQ-QUIC-HDR-0001
  - REQ-QUIC-HDR-0002
- Related:
  - [`SPEC-QUIC-HDR`](../../requirements/quic/SPEC-QUIC-HDR.md)
  - [`WI-QUIC-HDR-0001`](../../work-items/quic/WI-QUIC-HDR-0001.md)
  - [`VER-QUIC-HDR-0001`](../../verification/quic/VER-QUIC-HDR-0001.md)

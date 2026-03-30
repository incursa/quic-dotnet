---
artifact_id: WI-QUIC-HDR-0001
artifact_type: work_item
title: QUIC Header Parsing Work Item
domain: quic
status: planned
owner: quic-maintainers
addresses:
  - REQ-QUIC-HDR-0001
  - REQ-QUIC-HDR-0002
design_links:
  - ARC-QUIC-HDR-0001
verification_links:
  - VER-QUIC-HDR-0001
related_artifacts:
  - SPEC-QUIC-HDR
---

# [`WI-QUIC-HDR-0001`](./WI-QUIC-HDR-0001.md) - QUIC Header Parsing Work Item

## Scope

Keep the QUIC header parsing surface, tests, and evidence wiring aligned with
the header-parsing requirements.

## Delivery Tasks

- Keep the packet-form discriminator strict in [`QuicPacketParser`](../../../src/Incursa.Quic/QuicPacketParser.cs).
- Preserve the packet-specific parsing model in the header packet types.
- Keep the fuzz and property tests aligned with the parser contract.
- Keep benchmark coverage for the header parsing path in place.

## Trace Links

- Addresses:
  - REQ-QUIC-HDR-0001
  - REQ-QUIC-HDR-0002
- Uses Design:
  - [`ARC-QUIC-HDR-0001`](../../architecture/quic/ARC-QUIC-HDR-0001.md)
- Verified By:
  - [`VER-QUIC-HDR-0001`](../../verification/quic/VER-QUIC-HDR-0001.md)

## Related Code And Tests

- [`QuicPacketParser.cs`](../../../src/Incursa.Quic/QuicPacketParser.cs)
- [`QuicLongHeaderPacket.cs`](../../../src/Incursa.Quic/QuicLongHeaderPacket.cs)
- [`QuicShortHeaderPacket.cs`](../../../src/Incursa.Quic/QuicShortHeaderPacket.cs)
- [`QuicPacketParserTests.cs`](../../../tests/Incursa.Quic.Tests/QuicPacketParserTests.cs)
- [`QuicHeaderPropertyTests.cs`](../../../tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs)
- [`QuicHeaderFuzzTests.cs`](../../../tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs)
- [`QuicHeaderParsingBenchmarks.cs`](../../../benchmarks/QuicHeaderParsingBenchmarks.cs)

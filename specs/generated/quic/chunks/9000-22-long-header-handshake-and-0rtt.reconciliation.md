# Chunk Reconciliation: 9000-22-long-header-handshake-and-0rtt

## Requirements In Scope
- `S17P2P1`: 20 requirements (`REQ-QUIC-RFC9000-S17P2P1-0001` … `REQ-QUIC-RFC9000-S17P2P1-0020`)
- `S17P2P2`: 26 requirements (`REQ-QUIC-RFC9000-S17P2P2-0001` … `REQ-QUIC-RFC9000-S17P2P2-0026`)
- `S17P2P3`: 23 requirements (`REQ-QUIC-RFC9000-S17P2P3-0001` … `REQ-QUIC-RFC9000-S17P2P3-0023`)

## Requirements Completed
- implemented and tested: 27
- not implemented: 33
- partially implemented: 7
- tested but implementation mapping unclear: 2

## Existing Implementation Evidence
- [QuicPacketParser.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPacketParser.cs#L26) routes long-header vs Version Negotiation parsing and rejects non-VN long headers with a zero fixed bit.
- [QuicPacketParsing.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPacketParsing.cs#L9) parses the long-header envelope, including CID lengths and truncation handling, before exposing trailing bytes.
- [QuicLongHeaderPacket.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicLongHeaderPacket.cs#L31) now exposes `HeaderForm`, `FixedBit`, `LongPacketTypeBits`, `PacketNumberLengthBits`, `TypeSpecificBits`, `ReservedBits`, and `VersionSpecificData`.
- [QuicVersionNegotiationPacket.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicVersionNegotiationPacket.cs#L30) exposes the VN parse view and supported-version accessors.
- [PublicAPI.Unshipped.txt](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt#L13) records the new `PacketNumberLengthBits` surface.

## Existing Test Evidence
- [QuicPacketParserTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicPacketParserTests.cs#L17) covers header-form classification and first-byte control-bit preservation.
- [QuicLongHeaderPacketTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs#L17) covers long-header field round-tripping, packet-type bits, packet-number-length bits, truncation, and VN-state / CID-cap edge cases.
- [QuicHeaderPropertyTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs#L19) exercises property-based round-tripping for long headers and Version Negotiation packets.
- [QuicHeaderFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs#L17) exercises fuzzed round-tripping and truncation rejection for long headers and Version Negotiation packets.
- [QuicVersionNegotiationPacketTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs#L16) covers supported-version enumeration and malformed-input rejection.

## Old->New Requirement ID Mappings Applied
- Legacy header IDs 0008, 0009, and 0010 traits were rewritten to the canonical RFC 9000 Version Negotiation IDs in [QuicVersionNegotiationPacketTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs#L16).
- Generic `REQ-QUIC-RFC9000-S17P2-*` traits were rewritten in the shared long-header tests to the section-specific `REQ-QUIC-RFC9000-S17P2P1/P2/P3-*` IDs in [QuicLongHeaderPacketTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs#L17), [QuicHeaderPropertyTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs#L19), [QuicHeaderFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs#L17), and [QuicPacketParserTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicPacketParserTests.cs#L17).
- The only remaining legacy `REQ-QUIC-RFC9000-S17P2-0020` and `REQ-QUIC-RFC9000-S17P2-0021` traits are on the out-of-scope version-1 CID-cap tests in [QuicLongHeaderPacketTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs#L194) and were intentionally left untouched in this chunk.

## Gaps Fixed In This Pass
- Added [QuicLongHeaderPacket.PacketNumberLengthBits](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicLongHeaderPacket.cs#L51) and published it in [PublicAPI.Unshipped.txt](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt#L16).
- Retagged the long-header parser / property / fuzz tests to the canonical Initial / 0-RTT requirement IDs and added assertions for packet-number-length bits.
- Retagged the Version Negotiation tests to the canonical RFC 9000 IDs and removed stale requirement traits from helper-only negative tests that do not map cleanly to a requirement.

## Remaining Gaps
- tested but implementation mapping unclear: REQ-QUIC-RFC9000-S17P2P1-0010, REQ-QUIC-RFC9000-S17P2P1-0011
- partially implemented: REQ-QUIC-RFC9000-S17P2P2-0009, REQ-QUIC-RFC9000-S17P2P2-0011, REQ-QUIC-RFC9000-S17P2P2-0015, REQ-QUIC-RFC9000-S17P2P3-0001, REQ-QUIC-RFC9000-S17P2P3-0011, REQ-QUIC-RFC9000-S17P2P3-0012, REQ-QUIC-RFC9000-S17P2P3-0014
- not implemented: REQ-QUIC-RFC9000-S17P2P1-0001, REQ-QUIC-RFC9000-S17P2P1-0002, REQ-QUIC-RFC9000-S17P2P1-0012, REQ-QUIC-RFC9000-S17P2P1-0014, REQ-QUIC-RFC9000-S17P2P1-0015, REQ-QUIC-RFC9000-S17P2P1-0016, REQ-QUIC-RFC9000-S17P2P1-0017, REQ-QUIC-RFC9000-S17P2P1-0018, REQ-QUIC-RFC9000-S17P2P1-0020, REQ-QUIC-RFC9000-S17P2P2-0012, REQ-QUIC-RFC9000-S17P2P2-0013, REQ-QUIC-RFC9000-S17P2P2-0014, REQ-QUIC-RFC9000-S17P2P2-0017, REQ-QUIC-RFC9000-S17P2P2-0018, REQ-QUIC-RFC9000-S17P2P2-0019, REQ-QUIC-RFC9000-S17P2P2-0020, REQ-QUIC-RFC9000-S17P2P2-0021, REQ-QUIC-RFC9000-S17P2P2-0022, REQ-QUIC-RFC9000-S17P2P2-0023, REQ-QUIC-RFC9000-S17P2P2-0024, REQ-QUIC-RFC9000-S17P2P2-0025, REQ-QUIC-RFC9000-S17P2P2-0026, REQ-QUIC-RFC9000-S17P2P3-0003, REQ-QUIC-RFC9000-S17P2P3-0004, REQ-QUIC-RFC9000-S17P2P3-0015, REQ-QUIC-RFC9000-S17P2P3-0016, REQ-QUIC-RFC9000-S17P2P3-0017, REQ-QUIC-RFC9000-S17P2P3-0018, REQ-QUIC-RFC9000-S17P2P3-0019, REQ-QUIC-RFC9000-S17P2P3-0020, REQ-QUIC-RFC9000-S17P2P3-0021, REQ-QUIC-RFC9000-S17P2P3-0022, REQ-QUIC-RFC9000-S17P2P3-0023

## Requirements Needing Deeper Implementation Work
- Packet-number field parsing / encoding and packet-protection logic remain absent.
- Initial token-length and Length varint parsing remain absent.
- Packet-type-specific 160-bit CID enforcement for Initial and 0-RTT packets remains unimplemented.
- Initial / 0-RTT sender behavior, ACK handling, resend behavior, and early-data semantics remain unimplemented.

## Tests Run And Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicShortHeaderPacketTests"`
- Result: 40 passed, 0 failed, 0 skipped

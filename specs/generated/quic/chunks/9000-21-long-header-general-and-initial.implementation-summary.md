# 9000-21-long-header-general-and-initial Implementation Summary

## Requirements Completed

- `REQ-QUIC-RFC9000-S17-0001`
- `REQ-QUIC-RFC9000-S17P2-0001`
- `REQ-QUIC-RFC9000-S17P2-0002`
- `REQ-QUIC-RFC9000-S17P2-0003`
- `REQ-QUIC-RFC9000-S17P2-0004`
- `REQ-QUIC-RFC9000-S17P2-0005`
- `REQ-QUIC-RFC9000-S17P2-0006`
- `REQ-QUIC-RFC9000-S17P2-0007`
- `REQ-QUIC-RFC9000-S17P2-0008`
- `REQ-QUIC-RFC9000-S17P2-0009`
- `REQ-QUIC-RFC9000-S17P2-0012`
- `REQ-QUIC-RFC9000-S17P2-0013`
- `REQ-QUIC-RFC9000-S17P2-0014`
- `REQ-QUIC-RFC9000-S17P2-0015`
- `REQ-QUIC-RFC9000-S17P2-0016`
- `REQ-QUIC-RFC9000-S17P2-0017`
- `REQ-QUIC-RFC9000-S17P2-0018`
- `REQ-QUIC-RFC9000-S17P2-0019`
- `REQ-QUIC-RFC9000-S17P2-0020`
- `REQ-QUIC-RFC9000-S17P2-0021`
- `REQ-QUIC-RFC9000-S17P2-0023`
- `REQ-QUIC-RFC9000-S17P2-0024`
- `REQ-QUIC-RFC9000-S17P2-0025`
- `REQ-QUIC-RFC9000-S17P2-0027`
- This pass specifically closed the long-header fixed-bit and bitfield gaps in `0002`-`0004`, `0014`-`0016`, and `0027`.

## Files Changed

- `src/Incursa.Quic/QuicPacketParsing.cs`
- `src/Incursa.Quic/QuicPacketParser.cs`
- `src/Incursa.Quic/QuicLongHeaderPacket.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs`
- `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs`
- `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`
- `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs`

## Tests Added Or Updated

- Added `QuicLongHeaderPacketTests.TryParseLongHeader_RejectsNonVersionNegotiationPacketsWithZeroFixedBit`.
- Updated `QuicLongHeaderPacketTests.TryParseLongHeader_RoundTripsLengthEncodedConnectionIdsAndPayload` to assert the fixed bit, long packet type bits, type-specific bits, and reserved bits.
- Updated `QuicLongHeaderPacketTests.TryParseLongHeader_RejectsTruncatedInputs`, `TryParseLongHeader_RejectsPacketsMissingTheSourceConnectionIdLengthByte`, `TryParseLongHeader_AcceptsMaximumLengthConnectionIds`, `TryParseLongHeader_AllowsVersion1DestinationConnectionIdUpTo20Bytes`, and `TryParseLongHeader_RejectsVersion1DestinationConnectionIdLongerThan20Bytes` to use valid long-header inputs after the new fixed-bit validation.
- Updated `QuicHeaderPropertyTests.TryParseLongHeader_RoundTripsHeaderFields` to cover the new long-header bitfield properties.
- Updated `QuicHeaderPropertyGenerators.LongHeaderScenario` so property-based long-header cases always generate valid fixed-bit-on packets.
- Updated `QuicHeaderFuzzTests.Fuzz_LongHeaderParsing_RoundTripsValidInputsAndRejectsTruncation` to generate valid non-Version Negotiation long headers and assert the derived bitfields.
- Retagged the in-scope header-trace tests in `QuicPacketParserTests`, `QuicHeaderPropertyTests`, `QuicHeaderFuzzTests`, and `QuicLongHeaderPacketTests` to the canonical imported RFC 9000 requirement IDs.

## Tests Run And Results

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicShortHeaderPacketTests"`
- Result: passed
- Summary: 38 passed, 0 failed, 0 skipped

## Remaining Open Requirements In Scope

- `REQ-QUIC-RFC9000-S17P1-0001`
- `REQ-QUIC-RFC9000-S17P1-0002`
- `REQ-QUIC-RFC9000-S17P1-0003`
- `REQ-QUIC-RFC9000-S17P1-0004`
- `REQ-QUIC-RFC9000-S17P2-0010`
- `REQ-QUIC-RFC9000-S17P2-0011`
- `REQ-QUIC-RFC9000-S17P2-0022`
- `REQ-QUIC-RFC9000-S17P2-0026`
- `REQ-QUIC-RFC9000-S17P2-0028`
- `REQ-QUIC-RFC9000-S17P2-0029`
- `REQ-QUIC-RFC9000-S17P2-0030`
- `REQ-QUIC-RFC9000-S17P2-0031`
- `REQ-QUIC-RFC9000-S17P2-0032`
- `REQ-QUIC-RFC9000-S17P2-0033`

## Risks Or Follow-Up Notes

- `REQ-QUIC-RFC9000-S17P2-0022` remains parser-side capability proof only; the repo still has no server-side Version Negotiation formation path.
- `REQ-QUIC-RFC9000-S17P2-0026` still stops at preserving opaque trailing bytes; later packet-type-specific long-header fields are not parsed here.
- `REQ-QUIC-RFC9000-S17P2-0028` and `REQ-QUIC-RFC9000-S17P2-0029` remain blocked by the missing packet-protection pipeline.
- `REQ-QUIC-RFC9000-S17P2-0030` is still a security review item with no direct local code artifact.
- `REQ-QUIC-RFC9000-S17P2-0031`-`REQ-QUIC-RFC9000-S17P2-0033` remain blocked by the absence of packet-number parsing and encoding work.

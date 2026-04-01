# Chunk Reconciliation: 9000-23-retry-version-short-header

## Summary

- RFC: `9000`
- Section tokens: `S17P2P4`, `S17P2P5`, `S17P2P5P1`, `S17P2P5P2`, `S17P2P5P3`, `S17P3`, `S17P3P1`, `S17P4`
- Requirements in scope: 96
- Implemented and tested: 14
- Tested but implementation mapping unclear: 20
- Not implemented: 62

## Files Changed

- `src/Incursa.Quic/QuicPacketParser.cs`
- `src/Incursa.Quic/QuicShortHeaderPacket.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicHeaderTestData.cs`
- `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs`
- `tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs`
- `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs`
- `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`
- `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`

## Tests Run

- dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests\|FullyQualifiedName~QuicShortHeaderPacketTests\|FullyQualifiedName~QuicHeaderPropertyTests\|FullyQualifiedName~QuicHeaderFuzzTests\|FullyQualifiedName~QuicVersionNegotiationPacketTests\|FullyQualifiedName~QuicLongHeaderPacketTests"
- Result: 62 passed, 0 failed, 0 skipped

## Old -> New Requirement ID Mappings Applied

- Legacy header ID 0007 was rewritten to the canonical RFC 9000 short-header IDs across `tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs`.

## Gaps Fixed in This Pass

- Added short-header bitfield accessors to `src/Incursa.Quic/QuicShortHeaderPacket.cs`.
- Added fixed-bit validation to `src/Incursa.Quic/QuicPacketParser.cs` for short-header packets.
- Updated `tests/Incursa.Quic.Tests/QuicHeaderTestData.cs` and `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs` to generate valid short headers with the fixed bit set.
- Added and updated short-header parser, property, and fuzz tests to assert the parsed bit layout and rejection of invalid fixed-bit-zero packets.

## Requirements in Scope

### S17P2P4
- `REQ-QUIC-RFC9000-S17P2P4-0001` - not implemented - A Handshake packet MUST use long headers with a type value of 0x02, followed by the Length an...
- `REQ-QUIC-RFC9000-S17P2P4-0002` - tested but implementation mapping unclear - The first byte MUST contain the Reserved and Packet Number Length bits; see Section 17.2
- `REQ-QUIC-RFC9000-S17P2P4-0003` - not implemented - It MUST be used to carry cryptographic handshake messages and acknowledgments from the server...
- `REQ-QUIC-RFC9000-S17P2P4-0004` - tested but implementation mapping unclear - The Header Form field MUST be 1 bits long with value 1
- `REQ-QUIC-RFC9000-S17P2P4-0005` - tested but implementation mapping unclear - The Fixed Bit field MUST be 1 bits long with value 1
- `REQ-QUIC-RFC9000-S17P2P4-0006` - tested but implementation mapping unclear - The Long Packet Type field MUST be 2 bits long with value 2
- `REQ-QUIC-RFC9000-S17P2P4-0007` - tested but implementation mapping unclear - The Reserved Bits field MUST be 2 bits long
- `REQ-QUIC-RFC9000-S17P2P4-0008` - tested but implementation mapping unclear - The Packet Number Length field MUST be 2 bits long
- `REQ-QUIC-RFC9000-S17P2P4-0009` - tested but implementation mapping unclear - The Version field MUST be 32 bits long
- `REQ-QUIC-RFC9000-S17P2P4-0010` - tested but implementation mapping unclear - The Destination Connection ID Length field MUST be 8 bits long
- `REQ-QUIC-RFC9000-S17P2P4-0011` - tested but implementation mapping unclear - The Destination Connection ID field MUST be between 0 and 160 bits long
- `REQ-QUIC-RFC9000-S17P2P4-0012` - tested but implementation mapping unclear - The Source Connection ID Length field MUST be 8 bits long
- `REQ-QUIC-RFC9000-S17P2P4-0013` - tested but implementation mapping unclear - The Source Connection ID field MUST be between 0 and 160 bits long
- `REQ-QUIC-RFC9000-S17P2P4-0014` - tested but implementation mapping unclear - The Length field MUST be encoded as a variable-length integer
- `REQ-QUIC-RFC9000-S17P2P4-0015` - not implemented - The Packet Number field MUST be between 8 and 32 bits long
- `REQ-QUIC-RFC9000-S17P2P4-0016` - not implemented - Once a client has received a Handshake packet from a server, it MUST use Handshake packets to...
- `REQ-QUIC-RFC9000-S17P2P4-0017` - not implemented - The Destination Connection ID field in a Handshake packet MUST contain a connection ID that i...
- `REQ-QUIC-RFC9000-S17P2P4-0018` - not implemented - Handshake packets have their own packet number space, and thus the first Handshake packet sen...
- `REQ-QUIC-RFC9000-S17P2P4-0019` - not implemented - The payload of this packet MUST contain CRYPTO frames and could contain PING, PADDING, or ACK...
- `REQ-QUIC-RFC9000-S17P2P4-0020` - not implemented - Handshake packets MAY contain CONNECTION_CLOSE frames of type 0x1c
- `REQ-QUIC-RFC9000-S17P2P4-0021` - not implemented - Endpoints MUST treat receipt of Handshake packets with other frames as a connection error of...

### S17P2P5
- `REQ-QUIC-RFC9000-S17P2P5-0001` - not implemented - As shown in Figure 18, a Retry packet MUST use a long packet header with a type value of 0x03
- `REQ-QUIC-RFC9000-S17P2P5-0002` - not implemented - It MUST be used by a server that wishes to perform a retry; see Section 8.1
- `REQ-QUIC-RFC9000-S17P2P5-0003` - tested but implementation mapping unclear - The Header Form field MUST be 1 bits long with value 1
- `REQ-QUIC-RFC9000-S17P2P5-0004` - tested but implementation mapping unclear - The Fixed Bit field MUST be 1 bits long with value 1
- `REQ-QUIC-RFC9000-S17P2P5-0005` - tested but implementation mapping unclear - The Long Packet Type field MUST be 2 bits long with value 3
- `REQ-QUIC-RFC9000-S17P2P5-0006` - tested but implementation mapping unclear - The Unused field MUST be 4 bits long
- `REQ-QUIC-RFC9000-S17P2P5-0007` - tested but implementation mapping unclear - The Version field MUST be 32 bits long
- `REQ-QUIC-RFC9000-S17P2P5-0008` - tested but implementation mapping unclear - The Destination Connection ID Length field MUST be 8 bits long
- `REQ-QUIC-RFC9000-S17P2P5-0009` - tested but implementation mapping unclear - The Destination Connection ID field MUST be between 0 and 160 bits long
- `REQ-QUIC-RFC9000-S17P2P5-0010` - tested but implementation mapping unclear - The Source Connection ID Length field MUST be 8 bits long
- `REQ-QUIC-RFC9000-S17P2P5-0011` - tested but implementation mapping unclear - The Source Connection ID field MUST be between 0 and 160 bits long
- `REQ-QUIC-RFC9000-S17P2P5-0012` - not implemented - The Retry Integrity Tag field MUST be 128 bits long
- `REQ-QUIC-RFC9000-S17P2P5-0013` - not implemented - A Retry packet MUST NOT contain any protected fields
- `REQ-QUIC-RFC9000-S17P2P5-0014` - not implemented - The value in the Unused field is set to an arbitrary value by the server; a client MUST ignor...
- `REQ-QUIC-RFC9000-S17P2P5-0015` - not implemented - In addition to the fields from the long header, it MUST contain these additional fields:
- `REQ-QUIC-RFC9000-S17P2P5-0016` - not implemented - An opaque token that the server MAY use to validate the client's address

### S17P2P5P1
- `REQ-QUIC-RFC9000-S17P2P5P1-0001` - not implemented - The server MUST include a connection ID of its choice in the Source Connection ID field
- `REQ-QUIC-RFC9000-S17P2P5P1-0002` - not implemented - This value MUST NOT be equal to the Destination Connection ID field of the packet sent by the...
- `REQ-QUIC-RFC9000-S17P2P5P1-0003` - not implemented - A client MUST discard a Retry packet that contains a Source Connection ID field that is ident...
- `REQ-QUIC-RFC9000-S17P2P5P1-0004` - not implemented - The client MUST use the value from the Source Connection ID field of the Retry packet in the...
- `REQ-QUIC-RFC9000-S17P2P5P1-0005` - not implemented - A server MAY send Retry packets in response to Initial and 0-RTT packets
- `REQ-QUIC-RFC9000-S17P2P5P1-0006` - not implemented - A server MAY either discard or buffer 0-RTT packets that it receives
- `REQ-QUIC-RFC9000-S17P2P5P1-0007` - not implemented - A server MAY send multiple Retry packets as it receives Initial or 0-RTT packets
- `REQ-QUIC-RFC9000-S17P2P5P1-0008` - not implemented - A server MUST NOT send more than one Retry packet in response to a single UDP datagram

### S17P2P5P2
- `REQ-QUIC-RFC9000-S17P2P5P2-0001` - not implemented - A client MUST accept and process at most one Retry packet for each connection attempt
- `REQ-QUIC-RFC9000-S17P2P5P2-0002` - not implemented - After the client has received and processed an Initial or Retry packet from the server, it MU...
- `REQ-QUIC-RFC9000-S17P2P5P2-0003` - not implemented - Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot be validated;...
- `REQ-QUIC-RFC9000-S17P2P5P2-0004` - not implemented - A client MUST discard a Retry packet with a zero-length Retry Token field
- `REQ-QUIC-RFC9000-S17P2P5P2-0005` - not implemented - The client responds to a Retry packet with an Initial packet that MUST include the provided R...
- `REQ-QUIC-RFC9000-S17P2P5P2-0006` - not implemented - A client MUST set the Destination Connection ID field of this Initial packet to the value fro...
- `REQ-QUIC-RFC9000-S17P2P5P2-0007` - not implemented - It also MUST set the Token field to the token provided in the Retry packet
- `REQ-QUIC-RFC9000-S17P2P5P2-0008` - not implemented - The client MUST NOT change the Source Connection ID because the server could include the conn...
- `REQ-QUIC-RFC9000-S17P2P5P2-0009` - not implemented - A Retry packet does not include a packet number and MUST NOT be explicitly acknowledged by a...

### S17P2P5P3
- `REQ-QUIC-RFC9000-S17P2P5P3-0001` - not implemented - Subsequent Initial packets from the client MUST include the connection ID and token values fr...
- `REQ-QUIC-RFC9000-S17P2P5P3-0002` - not implemented - The client copies the Source Connection ID field from the Retry packet to the Destination Con...
- `REQ-QUIC-RFC9000-S17P2P5P3-0003` - not implemented - A client MUST use the same cryptographic handshake message it included in this packet
- `REQ-QUIC-RFC9000-S17P2P5P3-0004` - not implemented - A server MAY treat a packet that contains a different cryptographic handshake message as a co...
- `REQ-QUIC-RFC9000-S17P2P5P3-0005` - not implemented - A client MAY attempt 0-RTT after receiving a Retry packet by sending 0-RTT packets to the con...
- `REQ-QUIC-RFC9000-S17P2P5P3-0006` - not implemented - A client MUST NOT reset the packet number for any packet number space after processing a Retr...
- `REQ-QUIC-RFC9000-S17P2P5P3-0007` - not implemented - In particular, 0-RTT packets MUST contain confidential information that will most likely be r...
- `REQ-QUIC-RFC9000-S17P2P5P3-0008` - not implemented - A server MAY abort the connection if it detects that the client reset the packet number

### S17P3
- `REQ-QUIC-RFC9000-S17P3-0001` - tested but implementation mapping unclear - This version of QUIC defines a single packet type that MUST use the short packet header

### S17P3P1
- `REQ-QUIC-RFC9000-S17P3P1-0001` - not implemented - A 1-RTT packet MUST use a short packet header
- `REQ-QUIC-RFC9000-S17P3P1-0002` - not implemented - It MUST be used after the version and 1-RTT keys are negotiated
- `REQ-QUIC-RFC9000-S17P3P1-0003` - implemented and tested - The Header Form field MUST be 1 bits long with value 0
- `REQ-QUIC-RFC9000-S17P3P1-0004` - implemented and tested - The Fixed Bit field MUST be 1 bits long with value 1
- `REQ-QUIC-RFC9000-S17P3P1-0005` - implemented and tested - The Spin Bit field MUST be 1 bits long
- `REQ-QUIC-RFC9000-S17P3P1-0006` - implemented and tested - The Reserved Bits field MUST be 2 bits long
- `REQ-QUIC-RFC9000-S17P3P1-0007` - implemented and tested - The Key Phase field MUST be 1 bits long
- `REQ-QUIC-RFC9000-S17P3P1-0008` - implemented and tested - The Packet Number Length field MUST be 2 bits long
- `REQ-QUIC-RFC9000-S17P3P1-0009` - not implemented - The Destination Connection ID field MUST be between 0 and 160 bits long
- `REQ-QUIC-RFC9000-S17P3P1-0010` - not implemented - The Packet Number field MUST be between 8 and 32 bits long
- `REQ-QUIC-RFC9000-S17P3P1-0011` - not implemented - 1-RTT packets MUST contain the following fields:
- `REQ-QUIC-RFC9000-S17P3P1-0012` - implemented and tested - The most significant bit (0x80) of byte 0 MUST be set to 0 for the short header
- `REQ-QUIC-RFC9000-S17P3P1-0013` - implemented and tested - The next bit (0x40) of byte 0 MUST be set to 1
- `REQ-QUIC-RFC9000-S17P3P1-0014` - implemented and tested - Packets containing a zero value for this bit are not valid packets in this version and MUST b...
- `REQ-QUIC-RFC9000-S17P3P1-0015` - implemented and tested - The next two bits (those with a mask of 0x18) of byte 0 MUST be reserved
- `REQ-QUIC-RFC9000-S17P3P1-0016` - implemented and tested - The value included prior to protection MUST be set to 0
- `REQ-QUIC-RFC9000-S17P3P1-0017` - implemented and tested - An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both packet and header protection, as a connection error of type PROTOCOL_VIOLATION

## Existing Implementation Evidence

- `src/Incursa.Quic/QuicPacketParser.cs` now rejects short-header packets when the fixed bit is clear or the reserved bits are non-zero.
- `src/Incursa.Quic/QuicShortHeaderPacket.cs` exposes the short-header bitfield accessors used by the tests.
- The shared long-header parser and packet model in `src/Incursa.Quic/QuicPacketParsing.cs` and `src/Incursa.Quic/QuicLongHeaderPacket.cs` still provide the common envelope parsing used by the indirect Handshake/Retry coverage.

## Existing Test Evidence

- `tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs` covers positive parsing and both fixed-bit-zero and reserved-bits-non-zero rejection.
- `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs` covers header-form classification and short-header bit preservation.
- `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs` covers short-header round-tripping with generated scenarios.
- `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs` adds random short-header round-tripping and invalid fixed-bit / reserved-bits rejection.

## Remaining Gaps

- Handshake packet semantics and Retry packet semantics remain unmodeled as dedicated packet types.
- Retry integrity-tag, token, and client/server Retry behavior remain unimplemented.
- 1-RTT packet-number parsing, packet-type negotiation, and spin-bit state remain unimplemented.

## Requirements Needing Deeper Implementation Work

- `S17P2P4` Handshake packet behavior beyond the shared long-header envelope.
- `S17P2P5`, `S17P2P5P1`, `S17P2P5P2`, and `S17P2P5P3` Retry packet behavior and client/server reaction rules.
- `S17P3P1` requirements tied to packet numbers and 1-RTT state transitions.
- `S17P4` spin-bit toggling, disable controls, and observability behavior.

## Notes

- The live short-header traits no longer point at the legacy header ID 0007 alias.
- Generated repo-wide inventory files still mention the legacy alias in their historical summary text, but no live code or tests in this chunk do.

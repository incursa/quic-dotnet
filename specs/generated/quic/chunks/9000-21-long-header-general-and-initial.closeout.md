# 9000-21-long-header-general-and-initial Closeout

## Scope

- RFC: 9000
- Section tokens: `S17`, `S17P1`, `S17P2`
- Canonical spec: [`SPEC-QUIC-RFC9000.json`](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.json)

## Requirements in Scope

| Requirement ID | Title | Completion Status | Evidence | Note |
| --- | --- | --- | --- | --- |
| `REQ-QUIC-RFC9000-S17-0001` | All numeric values MUST be encoded in network byte order (that is, big endian), and all field... | implemented and tested | implementation and test evidence | Big-endian numeric ordering is exercised via the parser and test-data builders. |
| `REQ-QUIC-RFC9000-S17P2-0001` | The Header Form field MUST be 1 bits long with value 1 | implemented and tested | implementation and test evidence | Header-form classification is shared across the parser and long-header tests. |
| `REQ-QUIC-RFC9000-S17P2-0005` | The Version field MUST be 32 bits long | implemented and tested | implementation and test evidence | Version parsing is shared by the parser, packet model, and builders. |
| `REQ-QUIC-RFC9000-S17P2-0006` | The Destination Connection ID Length field MUST be 8 bits long | implemented and tested | implementation and test evidence | Destination CID length-byte parsing is direct and round-tripped. |
| `REQ-QUIC-RFC9000-S17P2-0007` | The Destination Connection ID field MUST be between 0 and 160 bits long | implemented and tested | implementation and test evidence | Version 1 is capped at 20 bytes and non-v1 long headers still exercise longer CID reads. |
| `REQ-QUIC-RFC9000-S17P2-0008` | The Source Connection ID Length field MUST be 8 bits long | implemented and tested | implementation and test evidence | Source CID length-byte parsing is direct and round-tripped. |
| `REQ-QUIC-RFC9000-S17P2-0009` | The Source Connection ID field MUST be between 0 and 160 bits long | implemented and tested | implementation and test evidence | Source CID slicing follows the encoded length and the non-v1 long-CID test still passes. |
| `REQ-QUIC-RFC9000-S17P2-0012` | Packets that use the long header MUST contain the following fields: | implemented and tested | implementation and test evidence | The long-header envelope is parsed and the control bits are preserved. |
| `REQ-QUIC-RFC9000-S17P2-0013` | The most significant bit (0x80) of byte 0 (the first byte) MUST be set to 1 for long headers | implemented and tested | implementation and test evidence | The first-byte high bit is used to classify long headers. |
| `REQ-QUIC-RFC9000-S17P2-0017` | This field MUST indicate the version of QUIC that is in use and determines how the rest of th... | implemented and tested | implementation and test evidence | Version zero maps to the Version Negotiation parse state. |
| `REQ-QUIC-RFC9000-S17P2-0018` | The byte following the version MUST contain the length in bytes of the Destination Connection... | implemented and tested | implementation and test evidence | The destination CID field is sliced using the encoded length. |
| `REQ-QUIC-RFC9000-S17P2-0019` | This length MUST be encoded as an 8-bit unsigned integer | implemented and tested | implementation and test evidence | The destination CID length remains an 8-bit wire value. |
| `REQ-QUIC-RFC9000-S17P2-0023` | The Destination Connection ID field follows the Destination Connection ID Length field, which... | implemented and tested | implementation and test evidence | The destination CID field is sliced using the encoded length. |
| `REQ-QUIC-RFC9000-S17P2-0024` | The byte following the Destination Connection ID MUST contain the length in bytes of the Sour... | implemented and tested | implementation and test evidence | The source CID length byte is read after the destination CID field. |
| `REQ-QUIC-RFC9000-S17P2-0025` | The Source Connection ID field follows the Source Connection ID Length field, which MUST indi... | implemented and tested | implementation and test evidence | The source CID field is sliced using the encoded length. |
| `REQ-QUIC-RFC9000-S17P2-0020` | In QUIC version 1, this value MUST NOT exceed 20 bytes | implemented and tested | implementation and test evidence | Version 1 long headers with a destination CID up to 20 bytes are accepted. |
| `REQ-QUIC-RFC9000-S17P2-0021` | Endpoints that receive a version 1 long header with a value larger than 20 MUST drop the packet | implemented and tested | implementation and test evidence | Version 1 long headers with a destination CID longer than 20 bytes are rejected. |
| `REQ-QUIC-RFC9000-S17P2-0022` | In order to properly form a Version Negotiation packet, servers SHOULD be able to read longer... | tested but implementation mapping unclear | test evidence + blocker note | The parser can read longer non-v1 CIDs, but there is no server-side Version Negotiation formation path in this repo. |
| `REQ-QUIC-RFC9000-S17P2-0002` | The Fixed Bit field MUST be 1 bits long with value 1 | implemented and tested | implementation and test evidence | The fixed bit is validated for non-Version Negotiation long headers and exposed on the packet view. |
| `REQ-QUIC-RFC9000-S17P2-0003` | The Long Packet Type field MUST be 2 bits long | implemented and tested | implementation and test evidence | The long packet type bits are surfaced as a dedicated `LongPacketTypeBits` property. |
| `REQ-QUIC-RFC9000-S17P2-0004` | The Type-Specific Bits field MUST be 4 bits long | implemented and tested | implementation and test evidence | The 4-bit type-specific field is surfaced as a dedicated `TypeSpecificBits` property. |
| `REQ-QUIC-RFC9000-S17P2-0014` | The next bit (0x40) of byte 0 MUST be set to 1, unless the packet is a Version Negotiation pa... | implemented and tested | implementation and test evidence | Non-Version Negotiation long headers now enforce the fixed-bit requirement, while version-zero packets remain parsable as Version Negotiation state. |
| `REQ-QUIC-RFC9000-S17P2-0015` | Packets containing a zero value for this bit are not valid packets in this version and MUST b... | implemented and tested | implementation and test evidence | Packets with a zero fixed bit are discarded unless they are Version Negotiation packets. |
| `REQ-QUIC-RFC9000-S17P2-0016` | The next two bits (those with a mask of 0x30) of byte 0 MUST contain a packet type | implemented and tested | implementation and test evidence | The packet-type bits are extracted and exposed without changing the preserved header-control bits. |
| `REQ-QUIC-RFC9000-S17P2-0026` | While type-specific semantics for this version are described in the following sections, sever... | partially implemented | partial implementation | The later packet-type-specific long-header fields are not parsed in this chunk. |
| `REQ-QUIC-RFC9000-S17P2-0027` | Two bits (those with a mask of 0x0c) of byte 0 MUST be reserved across multiple packet types | implemented and tested | implementation and test evidence | The reserved bits are surfaced as a dedicated `ReservedBits` property; enforcement remains deferred to later packet-protection work. |
| `REQ-QUIC-RFC9000-S17P1-0001` | When present in long or short packet headers, they MUST be encoded in 1 to 4 bytes | not implemented | explicit blocker note | No packet-number encoding surface exists. |
| `REQ-QUIC-RFC9000-S17P1-0002` | Prior to receiving an acknowledgment for a packet number space, the full packet number MUST b... | not implemented | explicit blocker note | No packet-number-space acknowledgement state exists. |
| `REQ-QUIC-RFC9000-S17P1-0003` | After an acknowledgment is received for a packet number space, the sender MUST use a packet n... | not implemented | explicit blocker note | No sender-side packet-number sizing policy exists. |
| `REQ-QUIC-RFC9000-S17P1-0004` | An endpoint SHOULD use a large enough packet number encoding to allow the packet number to be... | not implemented | explicit blocker note | No packet-number recovery heuristic exists. |
| `REQ-QUIC-RFC9000-S17P2-0010` | Long headers MUST be used for packets that are sent prior to the establishment of 1-RTT keys | not implemented | explicit blocker note | No sender-path logic for pre-1-RTT packet selection. |
| `REQ-QUIC-RFC9000-S17P2-0011` | Once 1-RTT keys are available, a sender MUST switch to sending packets using the short header... | not implemented | explicit blocker note | No sender-path logic for switching to short headers after 1-RTT keys. |
| `REQ-QUIC-RFC9000-S17P2-0028` | The value included prior to protection MUST be set to 0 | not implemented | explicit blocker note | No encoder or protection stage zeroes the pre-protection value. |
| `REQ-QUIC-RFC9000-S17P2-0029` | An endpoint MUST treat receipt of a packet that has a non-zero value for these bits after rem... | not implemented | explicit blocker note | No post-protection protocol-error path. |
| `REQ-QUIC-RFC9000-S17P2-0031` | In packet types that MUST contain a Packet Number field, the least significant two bits (thos... | not implemented | explicit blocker note | Packet-number field parsing and encoding do not exist. |
| `REQ-QUIC-RFC9000-S17P2-0032` | The Packet Number field MUST be field is 1 to 4 bytes long | not implemented | explicit blocker note | Packet-number length handling is absent. |
| `REQ-QUIC-RFC9000-S17P2-0033` | The length of the Packet Number field MUST be encoded in the Packet Number Length bits of byt... | not implemented | explicit blocker note | Packet-number length bits are not modeled. |
| `REQ-QUIC-RFC9000-S17P2-0030` | Discarding such a packet after only removing header protection MAY expose the endpoint to att... | unclear / needs human review | explicit review note | No packet-protection stage exists, so this security note cannot be closed by local code or tests alone. |

## Consistency Check

- In-scope tests carry canonical RFC 9000 requirement traits only: [`QuicPacketParserTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicPacketParserTests.cs), [`QuicLongHeaderPacketTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs), [`QuicHeaderPropertyTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs), [`QuicHeaderFuzzTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs).
- `src/Incursa.Quic` contains no requirement traits or XML-comment requirement refs for this chunk.
- No stale or wrong requirement IDs remain in the selected chunk.
- Legacy header traits remain only in out-of-scope later-chunk test files.
- The generated reconciliation and implementation-summary artifacts retain historical mapping data by design.

## Remaining Open Requirements

- Covered: 24 requirements.
- Partial: `REQ-QUIC-RFC9000-S17P2-0026`.
- Needs review: `REQ-QUIC-RFC9000-S17P2-0022`, `REQ-QUIC-RFC9000-S17P2-0030`.
- Blocked: `REQ-QUIC-RFC9000-S17P1-0001`, `REQ-QUIC-RFC9000-S17P1-0002`, `REQ-QUIC-RFC9000-S17P1-0003`, `REQ-QUIC-RFC9000-S17P1-0004`, `REQ-QUIC-RFC9000-S17P2-0010`, `REQ-QUIC-RFC9000-S17P2-0011`, `REQ-QUIC-RFC9000-S17P2-0028`, `REQ-QUIC-RFC9000-S17P2-0029`, `REQ-QUIC-RFC9000-S17P2-0031`, `REQ-QUIC-RFC9000-S17P2-0032`, `REQ-QUIC-RFC9000-S17P2-0033`.

## Tests Run And Results

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicShortHeaderPacketTests"`
- Result: Passed
- Summary: 38 passed, 0 failed, 0 skipped

## Conclusion

- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is trace-consistent and ready for repo-wide trace/audit tooling, but it still has the documented open requirements above.

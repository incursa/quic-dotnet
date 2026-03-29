# 9000-22-long-header-handshake-and-0rtt Closeout

## Scope

- RFC: 9000
- Section tokens: `S17P2P1`, `S17P2P2`, `S17P2P3`
- Canonical spec: [`SPEC-QUIC-RFC9000.md`](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.md)

## Requirements in Scope

| Requirement ID | Title | Completion Status | Evidence | Note |
| --- | --- | --- | --- | --- |
| `REQ-QUIC-RFC9000-S17P2P1-0001` | The Version Negotiation packet is a response to a client packet that contains a version t... | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P1-0002` | It MUST only be sent by servers | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P1-0003` | The Header Form field MUST be 1 bits long with value 1 | implemented and tested | implementation and test evidence | Long headers are classified from the first-byte high bit. |
| `REQ-QUIC-RFC9000-S17P2P1-0004` | The Unused field MUST be 7 bits long | implemented and tested | implementation and test evidence | Version Negotiation packets preserve the 7-bit unused field without making parse decisions from its value. |
| `REQ-QUIC-RFC9000-S17P2P1-0005` | The Version field MUST be 32 bits long with value 0 | implemented and tested | implementation and test evidence | Version zero maps to Version Negotiation and is preserved by the parser. |
| `REQ-QUIC-RFC9000-S17P2P1-0006` | The Destination Connection ID Length field MUST be 8 bits long | implemented and tested | implementation and test evidence | The connection ID length byte is parsed as an 8-bit field and round-tripped by the parser and tests. |
| `REQ-QUIC-RFC9000-S17P2P1-0007` | The Destination Connection ID field MUST be between 0 and 2040 bits long | implemented and tested | implementation and test evidence | Version Negotiation packets can carry longer connection IDs when forming the packet. |
| `REQ-QUIC-RFC9000-S17P2P1-0008` | The Source Connection ID Length field MUST be 8 bits long | implemented and tested | implementation and test evidence | The connection ID length byte is parsed as an 8-bit field and round-tripped by the parser and tests. |
| `REQ-QUIC-RFC9000-S17P2P1-0009` | The Source Connection ID field MUST be between 0 and 2040 bits long | implemented and tested | implementation and test evidence | Version Negotiation packets can carry longer connection IDs when forming the packet. |
| `REQ-QUIC-RFC9000-S17P2P1-0010` | The value in the Unused field MUST be set to an arbitrary value by the server | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P1-0011` | Clients MUST ignore the value of this field | implemented and tested | implementation and test evidence | Version Negotiation parsing accepts arbitrary Unused-field values and preserves them without making parse decisions based on those bits. |
| `REQ-QUIC-RFC9000-S17P2P1-0012` | Where QUIC might be multiplexed with other protocols (see [RFC7983]), servers SHOULD set... | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P1-0013` | The Version field of a Version Negotiation packet MUST be set to 0x00000000 | implemented and tested | implementation and test evidence | Version zero is parsed as a Version Negotiation packet. |
| `REQ-QUIC-RFC9000-S17P2P1-0014` | The server MUST include the value from the Source Connection ID field of the packet it re... | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P1-0015` | The value for Source Connection ID MUST be copied from the Destination Connection ID of t... | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P1-0016` | Version-specific rules for the connection ID therefore MUST NOT influence a decision abou... | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P1-0017` | A Version Negotiation packet MUST NOT be acknowledged | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P1-0018` | It is only sent in response to a packet that MUST indicate an unsupported version; see Se... | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P1-0019` | The Version Negotiation packet MUST NOT include the Packet Number and Length fields prese... | implemented and tested | implementation and test evidence | Version Negotiation packets are parsed into a dedicated view that exposes the supported versions and preserves the unused bits. |
| `REQ-QUIC-RFC9000-S17P2P1-0020` | A server MUST NOT send more than one Version Negotiation packet in response to a single U... | blocked | explicit blocker note | Blocked by missing Version Negotiation decision, emission, and connection-state surfaces. |
| `REQ-QUIC-RFC9000-S17P2P2-0001` | An Initial packet MUST use long headers with a type value of 0x00 | implemented and tested | implementation and test evidence | The parser and packet view expose the Initial packet envelope fields, including the packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P2P2-0002` | The Header Form field MUST be 1 bits long with value 1 | implemented and tested | implementation and test evidence | Long headers are classified from the first-byte high bit. |
| `REQ-QUIC-RFC9000-S17P2P2-0003` | The Fixed Bit field MUST be 1 bits long with value 1 | implemented and tested | implementation and test evidence | Non-Version Negotiation long headers validate the fixed bit before accepting the packet. |
| `REQ-QUIC-RFC9000-S17P2P2-0004` | The Long Packet Type field MUST be 2 bits long with value 0 | implemented and tested | implementation and test evidence | The long-packet-type bits are exposed separately on the packet view. |
| `REQ-QUIC-RFC9000-S17P2P2-0005` | The Reserved Bits field MUST be 2 bits long | implemented and tested | implementation and test evidence | The reserved bits are surfaced on the packet view; enforcement is deferred to later packet-protection work. |
| `REQ-QUIC-RFC9000-S17P2P2-0006` | The Packet Number Length field MUST be 2 bits long | implemented and tested | implementation and test evidence | The packet-number-length bits are surfaced on the long-header view. |
| `REQ-QUIC-RFC9000-S17P2P2-0007` | The Version field MUST be 32 bits long | implemented and tested | implementation and test evidence | Version parsing is round-tripped, with version zero mapping to Version Negotiation. |
| `REQ-QUIC-RFC9000-S17P2P2-0008` | The Destination Connection ID Length field MUST be 8 bits long | implemented and tested | implementation and test evidence | The connection ID length byte is parsed as an 8-bit field and round-tripped by the parser and tests. |
| `REQ-QUIC-RFC9000-S17P2P2-0009` | The Destination Connection ID field MUST be between 0 and 160 bits long | implemented and tested | implementation and test evidence | Version-1 long headers reject connection IDs longer than 20 bytes. |
| `REQ-QUIC-RFC9000-S17P2P2-0010` | The Source Connection ID Length field MUST be 8 bits long | implemented and tested | implementation and test evidence | The connection ID length byte is parsed as an 8-bit field and round-tripped by the parser and tests. |
| `REQ-QUIC-RFC9000-S17P2P2-0011` | The Source Connection ID field MUST be between 0 and 160 bits long | implemented and tested | implementation and test evidence | Version-1 long headers reject connection IDs longer than 20 bytes. |
| `REQ-QUIC-RFC9000-S17P2P2-0012` | The Token Length field MUST be encoded as a variable-length integer | implemented and tested | implementation and test evidence | The parser requires a parseable varint length before accepting the packet. |
| `REQ-QUIC-RFC9000-S17P2P2-0013` | The Length field MUST be encoded as a variable-length integer | implemented and tested | implementation and test evidence | The parser requires a parseable varint length before accepting the packet. |
| `REQ-QUIC-RFC9000-S17P2P2-0014` | The Packet Number field MUST be between 8 and 32 bits long | implemented and tested | implementation and test evidence | The parser validates the packet-number bytes implied by the packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P2P2-0015` | The Initial packet MUST contain a long header as well as the Length and Packet Number fie... | implemented and tested | implementation and test evidence | Initial packets are parsed through the long-header view and the remaining handshake semantics stay deferred. |
| `REQ-QUIC-RFC9000-S17P2P2-0016` | The first byte MUST contain the Reserved and Packet Number Length bits; see also Section... | implemented and tested | implementation and test evidence | The packet-number-length bits are exposed on the long-header view. |
| `REQ-QUIC-RFC9000-S17P2P2-0017` | The Token Length field MUST be variable-length integer specifying the length of the Token... | implemented and tested | implementation and test evidence | The parser validates the token length before accepting the Initial packet. |
| `REQ-QUIC-RFC9000-S17P2P2-0018` | Reject non-zero Token Length on client receipt | blocked | explicit blocker note | Blocked by missing endpoint-role-aware Initial receive path; the parser cannot tell whether the local endpoint is a client. |
| `REQ-QUIC-RFC9000-S17P2P2-0019` | Set Token Length to 0 for server Initial packets | blocked | explicit blocker note | Blocked by missing Initial packet serialization and server send path. |
| `REQ-QUIC-RFC9000-S17P2P2-0020` | This protection does not provide confidentiality or integrity against attackers that can... | blocked | explicit blocker note | Blocked by missing Initial packet protection, CRYPTO frame parsing, and connection-level handshake state. |
| `REQ-QUIC-RFC9000-S17P2P2-0021` | The client and server use the Initial packet type for any packet that MUST contain an ini... | blocked | explicit blocker note | Blocked by missing Initial packet protection, CRYPTO frame parsing, and connection-level handshake state. |
| `REQ-QUIC-RFC9000-S17P2P2-0022` | This MUST include all cases where a new packet containing the initial cryptographic messa... | blocked | explicit blocker note | Blocked by missing Initial packet protection, CRYPTO frame parsing, and connection-level handshake state. |
| `REQ-QUIC-RFC9000-S17P2P2-0023` | A server MAY send multiple Initial packets | blocked | explicit blocker note | Blocked by missing Initial packet protection, CRYPTO frame parsing, and connection-level handshake state. |
| `REQ-QUIC-RFC9000-S17P2P2-0024` | The payload of an Initial packet MUST include a CRYPTO frame (or frames) containing a cry... | blocked | explicit blocker note | Blocked by missing Initial packet protection, CRYPTO frame parsing, and connection-level handshake state. |
| `REQ-QUIC-RFC9000-S17P2P2-0025` | An endpoint that receives an Initial packet containing other frames MAY either discard th... | blocked | explicit blocker note | Blocked by missing Initial packet protection, CRYPTO frame parsing, and connection-level handshake state. |
| `REQ-QUIC-RFC9000-S17P2P2-0026` | The first packet sent by a client always includes a CRYPTO frame that MUST contain the st... | blocked | explicit blocker note | Blocked by missing Initial packet protection, CRYPTO frame parsing, and connection-level handshake state. |
| `REQ-QUIC-RFC9000-S17P2P3-0001` | A 0-RTT packet MUST use long headers with a type value of 0x01, followed by the Length an... | implemented and tested | implementation and test evidence | 0-RTT packets are parsed through the long-header view and the remaining early-data semantics stay deferred. |
| `REQ-QUIC-RFC9000-S17P2P3-0002` | The first byte MUST contain the Reserved and Packet Number Length bits; see Section 17.2 | implemented and tested | implementation and test evidence | The packet-number-length bits are exposed on the long-header view. |
| `REQ-QUIC-RFC9000-S17P2P3-0003` | A 0-RTT packet MUST be used to carry "early" data from the client to the server as part o... | blocked | explicit blocker note | Blocked by missing TLS early-data negotiation and 0-RTT send/receive behavior. |
| `REQ-QUIC-RFC9000-S17P2P3-0004` | As part of the TLS handshake, the server MAY accept or reject this early data | blocked | explicit blocker note | Blocked by missing TLS early-data negotiation and 0-RTT send/receive behavior. |
| `REQ-QUIC-RFC9000-S17P2P3-0005` | The Header Form field MUST be 1 bits long with value 1 | implemented and tested | implementation and test evidence | Long headers are classified from the first-byte high bit. |
| `REQ-QUIC-RFC9000-S17P2P3-0006` | The Fixed Bit field MUST be 1 bits long with value 1 | implemented and tested | implementation and test evidence | Non-Version Negotiation long headers validate the fixed bit before accepting the packet. |
| `REQ-QUIC-RFC9000-S17P2P3-0007` | The Long Packet Type field MUST be 2 bits long with value 1 | implemented and tested | implementation and test evidence | The long-packet-type bits are exposed separately on the packet view. |
| `REQ-QUIC-RFC9000-S17P2P3-0008` | The Reserved Bits field MUST be 2 bits long | implemented and tested | implementation and test evidence | The reserved bits are surfaced on the packet view; enforcement is deferred to later packet-protection work. |
| `REQ-QUIC-RFC9000-S17P2P3-0009` | The Packet Number Length field MUST be 2 bits long | implemented and tested | implementation and test evidence | The packet-number-length bits are surfaced on the long-header view. |
| `REQ-QUIC-RFC9000-S17P2P3-0010` | The Version field MUST be 32 bits long | implemented and tested | implementation and test evidence | Version parsing is round-tripped, with version zero mapping to Version Negotiation. |
| `REQ-QUIC-RFC9000-S17P2P3-0011` | The Destination Connection ID Length field MUST be 8 bits long | implemented and tested | implementation and test evidence | The connection ID length byte is parsed as an 8-bit field and round-tripped by the parser and tests. |
| `REQ-QUIC-RFC9000-S17P2P3-0012` | The Destination Connection ID field MUST be between 0 and 160 bits long | implemented and tested | implementation and test evidence | Version-1 long headers reject connection IDs longer than 20 bytes. |
| `REQ-QUIC-RFC9000-S17P2P3-0013` | The Source Connection ID Length field MUST be 8 bits long | implemented and tested | implementation and test evidence | The connection ID length byte is parsed as an 8-bit field and round-tripped by the parser and tests. |
| `REQ-QUIC-RFC9000-S17P2P3-0014` | The Source Connection ID field MUST be between 0 and 160 bits long | implemented and tested | implementation and test evidence | Version-1 long headers reject connection IDs longer than 20 bytes. |
| `REQ-QUIC-RFC9000-S17P2P3-0015` | The Length field MUST be encoded as a variable-length integer | implemented and tested | implementation and test evidence | The parser requires a parseable varint length before accepting the packet. |
| `REQ-QUIC-RFC9000-S17P2P3-0016` | The Packet Number field MUST be between 8 and 32 bits long | implemented and tested | implementation and test evidence | The parser validates the packet-number bytes implied by the packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P2P3-0017` | A client SHOULD attempt to resend data in 0-RTT packets after it sends a new Initial packet | blocked | explicit blocker note | Blocked by missing 0-RTT transmission state, packet number management, and resend coordination. |
| `REQ-QUIC-RFC9000-S17P2P3-0018` | New packet numbers MUST be used for any new packets that are sent; as described in Sectio... | blocked | explicit blocker note | Blocked by missing 0-RTT transmission state, packet number management, and resend coordination. |
| `REQ-QUIC-RFC9000-S17P2P3-0019` | A client MUST NOT send 0-RTT packets once it starts processing 1-RTT packets from the server | blocked | explicit blocker note | Blocked by missing 0-RTT transmission state, packet number management, and resend coordination. |
| `REQ-QUIC-RFC9000-S17P2P3-0020` | This means that 0-RTT packets MUST NOT contain any response to frames from 1-RTT packets | blocked | explicit blocker note | Blocked by missing 0-RTT/1-RTT ACK handling, remembered transport limits, and connection state. |
| `REQ-QUIC-RFC9000-S17P2P3-0021` | For instance, a client MUST NOT send an ACK frame in a 0-RTT packet, because that can onl... | blocked | explicit blocker note | Blocked by missing 0-RTT/1-RTT ACK handling, remembered transport limits, and connection state. |
| `REQ-QUIC-RFC9000-S17P2P3-0022` | An acknowledgment for a 1-RTT packet MUST be carried in a 1-RTT packet | blocked | explicit blocker note | Blocked by missing 0-RTT/1-RTT ACK handling, remembered transport limits, and connection state. |
| `REQ-QUIC-RFC9000-S17P2P3-0023` | A server SHOULD treat a violation of remembered limits (Section 7.4.1) as a connection er... | blocked | explicit blocker note | Blocked by missing 0-RTT/1-RTT ACK handling, remembered transport limits, and connection state. |

## Consistency Check

- In-scope tests carry canonical RFC 9000 requirement traits only across the five scoped test files.
- `src/Incursa.Quic` contains no in-scope requirement traits or XML-comment requirement refs for this chunk.
- No stale or wrong requirement IDs remain in scope.
- The closeout reflects `41` covered requirements and `28` blocked requirements; no partial or needs-review items remain.

## Remaining Open Requirements

- Blocked: 28 requirements.
- S17P2P1: `REQ-QUIC-RFC9000-S17P2P1-0001`, `REQ-QUIC-RFC9000-S17P2P1-0002`, `REQ-QUIC-RFC9000-S17P2P1-0010`, `REQ-QUIC-RFC9000-S17P2P1-0012`, `REQ-QUIC-RFC9000-S17P2P1-0014`, `REQ-QUIC-RFC9000-S17P2P1-0015`, `REQ-QUIC-RFC9000-S17P2P1-0016`, `REQ-QUIC-RFC9000-S17P2P1-0017`, `REQ-QUIC-RFC9000-S17P2P1-0018`, `REQ-QUIC-RFC9000-S17P2P1-0020`
- S17P2P2: `REQ-QUIC-RFC9000-S17P2P2-0018`, `REQ-QUIC-RFC9000-S17P2P2-0019`, `REQ-QUIC-RFC9000-S17P2P2-0020`, `REQ-QUIC-RFC9000-S17P2P2-0021`, `REQ-QUIC-RFC9000-S17P2P2-0022`, `REQ-QUIC-RFC9000-S17P2P2-0023`, `REQ-QUIC-RFC9000-S17P2P2-0024`, `REQ-QUIC-RFC9000-S17P2P2-0025`, `REQ-QUIC-RFC9000-S17P2P2-0026`
- S17P2P3: `REQ-QUIC-RFC9000-S17P2P3-0003`, `REQ-QUIC-RFC9000-S17P2P3-0004`, `REQ-QUIC-RFC9000-S17P2P3-0017`, `REQ-QUIC-RFC9000-S17P2P3-0018`, `REQ-QUIC-RFC9000-S17P2P3-0019`, `REQ-QUIC-RFC9000-S17P2P3-0020`, `REQ-QUIC-RFC9000-S17P2P3-0021`, `REQ-QUIC-RFC9000-S17P2P3-0022`, `REQ-QUIC-RFC9000-S17P2P3-0023`

## Tests Run And Results

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicShortHeaderPacketTests"`
- Result: Passed
- Summary: 60 passed, 0 failed, 0 skipped

## Conclusion

- No stale requirement IDs remain in scope.
- No silent gaps remain in scope; the only open work is the explicitly blocked higher-level handshake and packet-protection behavior.
- The chunk is trace-consistent and ready for repo-wide trace/audit tooling.

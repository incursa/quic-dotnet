# 9000-23-retry-version-short-header Closeout

## Scope

- RFC: 9000
- Section tokens: `S17P2P4`, `S17P2P5`, `S17P2P5P1`, `S17P2P5P2`, `S17P2P5P3`, `S17P3`, `S17P3P1`, `S17P4`
- Canonical spec: [SPEC-QUIC-RFC9000.json](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.json)

## Summary

- Requirements in scope: 96
- Implemented and tested: 14
- Tested but implementation mapping unclear: 22
- Not implemented: 60

## Requirements in Scope

| Requirement ID | Title | Completion Status | Evidence | Note |
| --- | --- | --- | --- | --- |
| `REQ-QUIC-RFC9000-S17P2P4-0001` | A Handshake packet MUST use long headers with a type value of 0x02, followed by the Length an... | not implemented | explicit blocker note | Handshake packet type 0x02, packet-number parsing, frame validation, and connection-error behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0002` | The first byte MUST contain the Reserved and Packet Number Length bits; see Section 17.2 | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0003` | It MUST be used to carry cryptographic handshake messages and acknowledgments from the server... | not implemented | explicit blocker note | Handshake packet type 0x02, packet-number parsing, frame validation, and connection-error behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0004` | The Header Form field MUST be 1 bits long with value 1 | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0005` | The Fixed Bit field MUST be 1 bits long with value 1 | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0006` | The Long Packet Type field MUST be 2 bits long with value 2 | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0007` | The Reserved Bits field MUST be 2 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0008` | The Packet Number Length field MUST be 2 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0009` | The Version field MUST be 32 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0010` | The Destination Connection ID Length field MUST be 8 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0011` | The Destination Connection ID field MUST be between 0 and 160 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0012` | The Source Connection ID Length field MUST be 8 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0013` | The Source Connection ID field MUST be between 0 and 160 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0014` | The Length field MUST be encoded as a variable-length integer | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0015` | The Packet Number field MUST be between 8 and 32 bits long | not implemented | explicit blocker note | Handshake packet type 0x02, packet-number parsing, frame validation, and connection-error behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0016` | Once a client has received a Handshake packet from a server, it MUST use Handshake packets to... | not implemented | explicit blocker note | Handshake packet type 0x02, packet-number parsing, frame validation, and connection-error behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0017` | The Destination Connection ID field in a Handshake packet MUST contain a connection ID that i... | not implemented | explicit blocker note | Handshake packet type 0x02, packet-number parsing, frame validation, and connection-error behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0018` | Handshake packets have their own packet number space, and thus the first Handshake packet sen... | not implemented | explicit blocker note | Handshake packet type 0x02, packet-number parsing, frame validation, and connection-error behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0019` | The payload of this packet MUST contain CRYPTO frames and could contain PING, PADDING, or ACK... | not implemented | explicit blocker note | Handshake packet type 0x02, packet-number parsing, frame validation, and connection-error behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0020` | Handshake packets MAY contain CONNECTION_CLOSE frames of type 0x1c | not implemented | explicit blocker note | Handshake packet type 0x02, packet-number parsing, frame validation, and connection-error behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P4-0021` | Endpoints MUST treat receipt of Handshake packets with other frames as a connection error of... | not implemented | explicit blocker note | Handshake packet type 0x02, packet-number parsing, frame validation, and connection-error behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0001` | As shown in Figure 18, a Retry packet MUST use a long packet header with a type value of 0x03 | not implemented | explicit blocker note | Retry packet type 0x03, integrity-tag handling, token parsing, and server/client Retry semantics are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0002` | It MUST be used by a server that wishes to perform a retry; see Section 8.1 | not implemented | explicit blocker note | Retry packet type 0x03, integrity-tag handling, token parsing, and server/client Retry semantics are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0003` | The Header Form field MUST be 1 bits long with value 1 | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0004` | The Fixed Bit field MUST be 1 bits long with value 1 | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0005` | The Long Packet Type field MUST be 2 bits long with value 3 | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0006` | The Unused field MUST be 4 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0007` | The Version field MUST be 32 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0008` | The Destination Connection ID Length field MUST be 8 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0009` | The Destination Connection ID field MUST be between 0 and 160 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0010` | The Source Connection ID Length field MUST be 8 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0011` | The Source Connection ID field MUST be between 0 and 160 bits long | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0012` | The Retry Integrity Tag field MUST be 128 bits long | not implemented | explicit blocker note | Retry packet type 0x03, integrity-tag handling, token parsing, and server/client Retry semantics are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0013` | A Retry packet MUST NOT contain any protected fields | not implemented | explicit blocker note | Retry packet type 0x03, integrity-tag handling, token parsing, and server/client Retry semantics are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0014` | The value in the Unused field is set to an arbitrary value by the server; a client MUST ignor... | not implemented | explicit blocker note | Retry packet type 0x03, integrity-tag handling, token parsing, and server/client Retry semantics are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0015` | In addition to the fields from the long header, it MUST contain these additional fields: | not implemented | explicit blocker note | Retry packet type 0x03, integrity-tag handling, token parsing, and server/client Retry semantics are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5-0016` | An opaque token that the server MAY use to validate the client's address | not implemented | explicit blocker note | Retry packet type 0x03, integrity-tag handling, token parsing, and server/client Retry semantics are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P1-0001` | The server MUST include a connection ID of its choice in the Source Connection ID field | not implemented | explicit blocker note | Server Retry generation behavior is not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P1-0002` | This value MUST NOT be equal to the Destination Connection ID field of the packet sent by the... | not implemented | explicit blocker note | Server Retry generation behavior is not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P1-0003` | A client MUST discard a Retry packet that contains a Source Connection ID field that is ident... | not implemented | explicit blocker note | Server Retry generation behavior is not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P1-0004` | The client MUST use the value from the Source Connection ID field of the Retry packet in the... | not implemented | explicit blocker note | Server Retry generation behavior is not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P1-0005` | A server MAY send Retry packets in response to Initial and 0-RTT packets | not implemented | explicit blocker note | Server Retry generation behavior is not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P1-0006` | A server MAY either discard or buffer 0-RTT packets that it receives | not implemented | explicit blocker note | Server Retry generation behavior is not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P1-0007` | A server MAY send multiple Retry packets as it receives Initial or 0-RTT packets | not implemented | explicit blocker note | Server Retry generation behavior is not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P1-0008` | A server MUST NOT send more than one Retry packet in response to a single UDP datagram | not implemented | explicit blocker note | Server Retry generation behavior is not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P2-0001` | A client MUST accept and process at most one Retry packet for each connection attempt | not implemented | explicit blocker note | Client Retry processing and token-bearing Initial re-send behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P2-0002` | After the client has received and processed an Initial or Retry packet from the server, it MU... | not implemented | explicit blocker note | Client Retry processing and token-bearing Initial re-send behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P2-0003` | Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot be validated;... | not implemented | explicit blocker note | Client Retry processing and token-bearing Initial re-send behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P2-0004` | A client MUST discard a Retry packet with a zero-length Retry Token field | not implemented | explicit blocker note | Client Retry processing and token-bearing Initial re-send behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P2-0005` | The client responds to a Retry packet with an Initial packet that MUST include the provided R... | not implemented | explicit blocker note | Client Retry processing and token-bearing Initial re-send behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P2-0006` | A client MUST set the Destination Connection ID field of this Initial packet to the value fro... | not implemented | explicit blocker note | Client Retry processing and token-bearing Initial re-send behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P2-0007` | It also MUST set the Token field to the token provided in the Retry packet | not implemented | explicit blocker note | Client Retry processing and token-bearing Initial re-send behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P2-0008` | The client MUST NOT change the Source Connection ID because the server could include the conn... | not implemented | explicit blocker note | Client Retry processing and token-bearing Initial re-send behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P2-0009` | A Retry packet does not include a packet number and MUST NOT be explicitly acknowledged by a... | not implemented | explicit blocker note | Client Retry processing and token-bearing Initial re-send behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P3-0001` | Subsequent Initial packets from the client MUST include the connection ID and token values fr... | not implemented | explicit blocker note | Post-Retry 0-RTT and packet-number continuity behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P3-0002` | The client copies the Source Connection ID field from the Retry packet to the Destination Con... | not implemented | explicit blocker note | Post-Retry 0-RTT and packet-number continuity behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P3-0003` | A client MUST use the same cryptographic handshake message it included in this packet | not implemented | explicit blocker note | Post-Retry 0-RTT and packet-number continuity behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P3-0004` | A server MAY treat a packet that contains a different cryptographic handshake message as a co... | not implemented | explicit blocker note | Post-Retry 0-RTT and packet-number continuity behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P3-0005` | A client MAY attempt 0-RTT after receiving a Retry packet by sending 0-RTT packets to the con... | not implemented | explicit blocker note | Post-Retry 0-RTT and packet-number continuity behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P3-0006` | A client MUST NOT reset the packet number for any packet number space after processing a Retr... | not implemented | explicit blocker note | Post-Retry 0-RTT and packet-number continuity behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P3-0007` | In particular, 0-RTT packets MUST contain confidential information that will most likely be r... | not implemented | explicit blocker note | Post-Retry 0-RTT and packet-number continuity behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P2P5P3-0008` | A server MAY abort the connection if it detects that the client reset the packet number | not implemented | explicit blocker note | Post-Retry 0-RTT and packet-number continuity behavior are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P3-0001` | This version of QUIC defines a single packet type that MUST use the short packet header | tested but implementation mapping unclear | implementation and test evidence | Only the shared long-header envelope is present; no packet-type-specific Handshake/Retry model or state machine exists yet. |
| `REQ-QUIC-RFC9000-S17P3P1-0001` | A 1-RTT packet MUST use a short packet header | not implemented | explicit blocker note | 1-RTT packet number parsing and the short-header payload/state machine are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P3P1-0002` | It MUST be used after the version and 1-RTT keys are negotiated | not implemented | explicit blocker note | 1-RTT packet number parsing and the short-header payload/state machine are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P3P1-0003` | The Header Form field MUST be 1 bits long with value 0 | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0004` | The Fixed Bit field MUST be 1 bits long with value 1 | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0005` | The Spin Bit field MUST be 1 bits long | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0006` | The Reserved Bits field MUST be 2 bits long | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0007` | The Key Phase field MUST be 1 bits long | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0008` | The Packet Number Length field MUST be 2 bits long | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0009` | The Destination Connection ID field MUST be between 0 and 160 bits long | not implemented | explicit blocker note | 1-RTT packet number parsing and the short-header payload/state machine are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P3P1-0010` | The Packet Number field MUST be between 8 and 32 bits long | not implemented | explicit blocker note | 1-RTT packet number parsing and the short-header payload/state machine are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P3P1-0011` | 1-RTT packets MUST contain the following fields: | not implemented | explicit blocker note | 1-RTT packet number parsing and the short-header payload/state machine are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P3P1-0012` | The most significant bit (0x80) of byte 0 MUST be set to 0 for the short header | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0013` | The next bit (0x40) of byte 0 MUST be set to 1 | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0014` | Packets containing a zero value for this bit are not valid packets in this version and MUST b... | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0015` | The next two bits (those with a mask of 0x18) of byte 0 MUST be reserved | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0016` | The value included prior to protection MUST be set to 0 | implemented and tested | implementation and test evidence | Short-header reserved bits are now normalized in valid inputs and rejected when non-zero. |
| `REQ-QUIC-RFC9000-S17P3P1-0017` | An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after re... | implemented and tested | implementation and test evidence | Short-header reserved bits are now normalized in valid inputs and rejected when non-zero. |
| `REQ-QUIC-RFC9000-S17P3P1-0018` | Discarding such a packet after only removing header protection MAY expose the endpoint to att... | not implemented | explicit blocker note | 1-RTT packet number parsing and the short-header payload/state machine are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P3P1-0019` | The next bit (0x04) of byte 0 MUST indicate the key phase, which allows a recipient of a pack... | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0020` | The least significant two bits (those with a mask of 0x03) of byte 0 MUST contain the length... | implemented and tested | implementation and test evidence | Direct test evidence now exists for the short-header form, fixed bit, spin bit, reserved bits, key phase, and packet-number-length bits. |
| `REQ-QUIC-RFC9000-S17P3P1-0021` | The Packet Number field MUST be Packet Number field is 1 to 4 bytes long | not implemented | explicit blocker note | 1-RTT packet number parsing and the short-header payload/state machine are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P3P1-0022` | The length of the Packet Number field MUST be encoded in Packet Number Length field | not implemented | explicit blocker note | 1-RTT packet number parsing and the short-header payload/state machine are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P3P1-0023` | 1-RTT packets always MUST include a 1-RTT protected payload | not implemented | explicit blocker note | 1-RTT packet number parsing and the short-header payload/state machine are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0001` | On-path observers MAY measure the time between two spin bit toggle events to estimate the end... | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0002` | The spin bit MUST only be present in 1-RTT packets, since it is possible to measure the initi... | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0003` | An endpoint that does not support this feature MUST disable it, as defined below | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0004` | Implementations MUST allow administrators of clients and servers to disable the spin bit eith... | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0005` | Even when the spin bit is not disabled by the administrator, endpoints MUST disable their use... | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0006` | Allow any spin value when disabled | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0007` | Ignore any incoming spin value when disabled | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0008` | If the spin bit is enabled for the connection, the endpoint maintains a spin value for each n... | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0009` | When a server receives a 1-RTT packet that increases the highest packet number seen by the se... | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |
| `REQ-QUIC-RFC9000-S17P4-0010` | When a client receives a 1-RTT packet that increases the highest packet number seen by the cl... | not implemented | explicit blocker note | Spin-bit enable/disable behavior and packet-number-driven spin toggling are not implemented yet. |

## Consistency Check

- In-scope tests carry canonical RFC 9000 requirement traits only across the six scoped test files.
- `src/Incursa.Quic` contains no in-scope requirement traits or XML-comment requirement refs for this chunk.
- No stale or wrong requirement IDs remain in scope.
- The closeout reflects 14 covered requirements, 22 partial requirements, and 60 blocked requirements.

## Remaining Open Requirements

- `REQ-QUIC-RFC9000-S17P2P4-0001`
- `REQ-QUIC-RFC9000-S17P2P4-0002`
- `REQ-QUIC-RFC9000-S17P2P4-0003`
- `REQ-QUIC-RFC9000-S17P2P4-0004`
- `REQ-QUIC-RFC9000-S17P2P4-0005`
- `REQ-QUIC-RFC9000-S17P2P4-0006`
- `REQ-QUIC-RFC9000-S17P2P4-0007`
- `REQ-QUIC-RFC9000-S17P2P4-0008`
- `REQ-QUIC-RFC9000-S17P2P4-0009`
- `REQ-QUIC-RFC9000-S17P2P4-0010`
- `REQ-QUIC-RFC9000-S17P2P4-0011`
- `REQ-QUIC-RFC9000-S17P2P4-0012`
- `REQ-QUIC-RFC9000-S17P2P4-0013`
- `REQ-QUIC-RFC9000-S17P2P4-0014`
- `REQ-QUIC-RFC9000-S17P2P4-0015`
- `REQ-QUIC-RFC9000-S17P2P4-0016`
- `REQ-QUIC-RFC9000-S17P2P4-0017`
- `REQ-QUIC-RFC9000-S17P2P4-0018`
- `REQ-QUIC-RFC9000-S17P2P4-0019`
- `REQ-QUIC-RFC9000-S17P2P4-0020`
- `REQ-QUIC-RFC9000-S17P2P4-0021`
- `REQ-QUIC-RFC9000-S17P2P5-0001`
- `REQ-QUIC-RFC9000-S17P2P5-0002`
- `REQ-QUIC-RFC9000-S17P2P5-0003`
- `REQ-QUIC-RFC9000-S17P2P5-0004`
- `REQ-QUIC-RFC9000-S17P2P5-0005`
- `REQ-QUIC-RFC9000-S17P2P5-0006`
- `REQ-QUIC-RFC9000-S17P2P5-0007`
- `REQ-QUIC-RFC9000-S17P2P5-0008`
- `REQ-QUIC-RFC9000-S17P2P5-0009`
- `REQ-QUIC-RFC9000-S17P2P5-0010`
- `REQ-QUIC-RFC9000-S17P2P5-0011`
- `REQ-QUIC-RFC9000-S17P2P5-0012`
- `REQ-QUIC-RFC9000-S17P2P5-0013`
- `REQ-QUIC-RFC9000-S17P2P5-0014`
- `REQ-QUIC-RFC9000-S17P2P5-0015`
- `REQ-QUIC-RFC9000-S17P2P5-0016`
- `REQ-QUIC-RFC9000-S17P2P5P1-0001`
- `REQ-QUIC-RFC9000-S17P2P5P1-0002`
- `REQ-QUIC-RFC9000-S17P2P5P1-0003`
- `REQ-QUIC-RFC9000-S17P2P5P1-0004`
- `REQ-QUIC-RFC9000-S17P2P5P1-0005`
- `REQ-QUIC-RFC9000-S17P2P5P1-0006`
- `REQ-QUIC-RFC9000-S17P2P5P1-0007`
- `REQ-QUIC-RFC9000-S17P2P5P1-0008`
- `REQ-QUIC-RFC9000-S17P2P5P2-0001`
- `REQ-QUIC-RFC9000-S17P2P5P2-0002`
- `REQ-QUIC-RFC9000-S17P2P5P2-0003`
- `REQ-QUIC-RFC9000-S17P2P5P2-0004`
- `REQ-QUIC-RFC9000-S17P2P5P2-0005`
- `REQ-QUIC-RFC9000-S17P2P5P2-0006`
- `REQ-QUIC-RFC9000-S17P2P5P2-0007`
- `REQ-QUIC-RFC9000-S17P2P5P2-0008`
- `REQ-QUIC-RFC9000-S17P2P5P2-0009`
- `REQ-QUIC-RFC9000-S17P2P5P3-0001`
- `REQ-QUIC-RFC9000-S17P2P5P3-0002`
- `REQ-QUIC-RFC9000-S17P2P5P3-0003`
- `REQ-QUIC-RFC9000-S17P2P5P3-0004`
- `REQ-QUIC-RFC9000-S17P2P5P3-0005`
- `REQ-QUIC-RFC9000-S17P2P5P3-0006`
- `REQ-QUIC-RFC9000-S17P2P5P3-0007`
- `REQ-QUIC-RFC9000-S17P2P5P3-0008`
- `REQ-QUIC-RFC9000-S17P3-0001`
- `REQ-QUIC-RFC9000-S17P3P1-0001`
- `REQ-QUIC-RFC9000-S17P3P1-0002`
- `REQ-QUIC-RFC9000-S17P3P1-0009`
- `REQ-QUIC-RFC9000-S17P3P1-0010`
- `REQ-QUIC-RFC9000-S17P3P1-0011`
- `REQ-QUIC-RFC9000-S17P3P1-0018`
- `REQ-QUIC-RFC9000-S17P3P1-0021`
- `REQ-QUIC-RFC9000-S17P3P1-0022`
- `REQ-QUIC-RFC9000-S17P3P1-0023`
- `REQ-QUIC-RFC9000-S17P4-0001`
- `REQ-QUIC-RFC9000-S17P4-0002`
- `REQ-QUIC-RFC9000-S17P4-0003`
- `REQ-QUIC-RFC9000-S17P4-0004`
- `REQ-QUIC-RFC9000-S17P4-0005`
- `REQ-QUIC-RFC9000-S17P4-0006`
- `REQ-QUIC-RFC9000-S17P4-0007`
- `REQ-QUIC-RFC9000-S17P4-0008`
- `REQ-QUIC-RFC9000-S17P4-0009`
- `REQ-QUIC-RFC9000-S17P4-0010`

## Tests Run And Results

- dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicShortHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicLongHeaderPacketTests"
- Result: 63 passed, 0 failed, 0 skipped

## Conclusion

- No stale requirement IDs remain in scope.
- No silent gaps remain in scope; the remaining work is explicit partial or blocked trace coverage.
- The chunk is trace-consistent and ready for repo-wide trace/audit tooling.

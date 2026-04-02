# RFC 9000 Chunk Reconciliation: `9000-05-connection-id-management`

## Scope

Source: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
RFC: `9000`
Section tokens: `S5P1P2, S5P2, S5P2P1, S5P2P2, S5P2P3`

## Audit Result

- No stale requirement IDs were found under the touched src/test surfaces for this chunk.
- Current test traits carry the imported IDs for the wire-level slice in scope.
- Remaining work is isolated to explicit connection-state, packet-processing, and migration runtime gaps.

## Requirements in Scope

### `S5P1P2`

| Requirement | Status |
| --- | --- |
| `REQ-QUIC-RFC9000-S5P1P2-0001` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0002` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0003` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0004` | implemented and tested |
| `REQ-QUIC-RFC9000-S5P1P2-0005` | implemented and tested |
| `REQ-QUIC-RFC9000-S5P1P2-0006` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0007` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0008` | implemented and tested |
| `REQ-QUIC-RFC9000-S5P1P2-0009` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0010` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0011` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0012` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0013` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0014` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0015` | not implemented |
| `REQ-QUIC-RFC9000-S5P1P2-0016` | not implemented |

### `S5P2`

| Requirement | Status |
| --- | --- |
| `REQ-QUIC-RFC9000-S5P2-0001` | implemented and tested |
| `REQ-QUIC-RFC9000-S5P2-0002` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0003` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0004` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0005` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0006` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0007` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0008` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0009` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0010` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0011` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0012` | not implemented |
| `REQ-QUIC-RFC9000-S5P2-0013` | not implemented |

### `S5P2P1`

| Requirement | Status |
| --- | --- |
| `REQ-QUIC-RFC9000-S5P2P1-0001` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P1-0002` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P1-0003` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P1-0004` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P1-0005` | not implemented |

### `S5P2P2`

| Requirement | Status |
| --- | --- |
| `REQ-QUIC-RFC9000-S5P2P2-0001` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P2-0002` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P2-0003` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P2-0004` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P2-0005` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P2-0006` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P2-0007` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P2-0008` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P2-0009` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P2-0010` | not implemented |

### `S5P2P3`

| Requirement | Status |
| --- | --- |
| `REQ-QUIC-RFC9000-S5P2P3-0001` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P3-0002` | implemented and tested |
| `REQ-QUIC-RFC9000-S5P2P3-0003` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P3-0004` | implemented and tested |
| `REQ-QUIC-RFC9000-S5P2P3-0005` | not implemented |
| `REQ-QUIC-RFC9000-S5P2P3-0006` | not implemented |

## Requirements Completed

- `REQ-QUIC-RFC9000-S5P1P2-0004`: The on-wire RETIRE_CONNECTION_ID signal is now directly traced.
- `REQ-QUIC-RFC9000-S5P1P2-0005`: The no-reuse request is covered at the wire format layer by the RETIRE_CONNECTION_ID frame codec.
- `REQ-QUIC-RFC9000-S5P1P2-0008`: The wire-format Retire Prior To field is now directly traced.
- `REQ-QUIC-RFC9000-S5P2-0001`: Trace coverage was already present from the prior pass; the packet-classification hook is still a direct match for the imported ID.
- `REQ-QUIC-RFC9000-S5P2P3-0002`: The preferred_address transport parameter is encoded, parsed, and fuzzed; the remaining migration-policy clauses are tracked separately in this chunk.
- `REQ-QUIC-RFC9000-S5P2P3-0004`: The disable_active_migration transport parameter is directly traced at the wire level.

## Existing Implementation Evidence

- `src/Incursa.Quic/QuicPacketParser.cs:11-21` classifies packet header form on receipt.
- `src/Incursa.Quic/QuicFrameCodec.cs:655-756` parses and formats `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID` frames.
- `src/Incursa.Quic/QuicTransportParametersCodec.cs:18-20,73-152,161-454` parses and formats the transport parameters used by preferred-address and disable-active-migration signaling.
- `src/Incursa.Quic/QuicTransportParameters.cs:51-61` exposes the `DisableActiveMigration`, `PreferredAddress`, and `ActiveConnectionIdLimit` properties consumed by the codec.
- No requirement-tagged source comments were found in `src/Incursa.Quic` for this chunk.

## Existing Test Evidence

- `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs` and `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs` already carry `REQ-QUIC-RFC9000-S5P2-0001` for the packet-classification hook.
- `tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs` and `tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs` now cover the imported `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID` IDs in this chunk.
- `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs` and `tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs` now cover the imported preferred-address and disable-active-migration IDs in this chunk.

## Old -> New Requirement ID Mappings Applied

- None in this pass. The chunk was already using imported IDs where the mapping was clear.

## Gaps Fixed in This Pass

- Added `REQ-QUIC-RFC9000-S5P1P2-0004` and `REQ-QUIC-RFC9000-S5P1P2-0005` traits to the RETIRE_CONNECTION_ID frame round-trip and truncation tests, plus the part-4 fuzz slice.
- Added `REQ-QUIC-RFC9000-S5P1P2-0008` traits to the NEW_CONNECTION_ID frame round-trip and fuzz coverage.
- Added `REQ-QUIC-RFC9000-S5P2P3-0002` and `REQ-QUIC-RFC9000-S5P2P3-0004` traits to transport-parameter parse/format and fuzz coverage.
- Carried forward the existing `REQ-QUIC-RFC9000-S5P2-0001` packet-classification trace from the prior pass.

## Remaining Gaps

- `S5P1P2`: 13 open requirements (`REQ-QUIC-RFC9000-S5P1P2-0001`, `REQ-QUIC-RFC9000-S5P1P2-0002`, `REQ-QUIC-RFC9000-S5P1P2-0003`, `REQ-QUIC-RFC9000-S5P1P2-0006`, `REQ-QUIC-RFC9000-S5P1P2-0007`, `REQ-QUIC-RFC9000-S5P1P2-0009`, `REQ-QUIC-RFC9000-S5P1P2-0010`, `REQ-QUIC-RFC9000-S5P1P2-0011`, `REQ-QUIC-RFC9000-S5P1P2-0012`, `REQ-QUIC-RFC9000-S5P1P2-0013`, `REQ-QUIC-RFC9000-S5P1P2-0014`, `REQ-QUIC-RFC9000-S5P1P2-0015`, `REQ-QUIC-RFC9000-S5P1P2-0016`).
- `S5P2`: 12 open requirements (`REQ-QUIC-RFC9000-S5P2-0002`, `REQ-QUIC-RFC9000-S5P2-0003`, `REQ-QUIC-RFC9000-S5P2-0004`, `REQ-QUIC-RFC9000-S5P2-0005`, `REQ-QUIC-RFC9000-S5P2-0006`, `REQ-QUIC-RFC9000-S5P2-0007`, `REQ-QUIC-RFC9000-S5P2-0008`, `REQ-QUIC-RFC9000-S5P2-0009`, `REQ-QUIC-RFC9000-S5P2-0010`, `REQ-QUIC-RFC9000-S5P2-0011`, `REQ-QUIC-RFC9000-S5P2-0012`, `REQ-QUIC-RFC9000-S5P2-0013`).
- `S5P2P1`: 5 open requirements (`REQ-QUIC-RFC9000-S5P2P1-0001`, `REQ-QUIC-RFC9000-S5P2P1-0002`, `REQ-QUIC-RFC9000-S5P2P1-0003`, `REQ-QUIC-RFC9000-S5P2P1-0004`, `REQ-QUIC-RFC9000-S5P2P1-0005`).
- `S5P2P2`: 10 open requirements (`REQ-QUIC-RFC9000-S5P2P2-0001`, `REQ-QUIC-RFC9000-S5P2P2-0002`, `REQ-QUIC-RFC9000-S5P2P2-0003`, `REQ-QUIC-RFC9000-S5P2P2-0004`, `REQ-QUIC-RFC9000-S5P2P2-0005`, `REQ-QUIC-RFC9000-S5P2P2-0006`, `REQ-QUIC-RFC9000-S5P2P2-0007`, `REQ-QUIC-RFC9000-S5P2P2-0008`, `REQ-QUIC-RFC9000-S5P2P2-0009`, `REQ-QUIC-RFC9000-S5P2P2-0010`).
- `S5P2P3`: 4 open requirements (`REQ-QUIC-RFC9000-S5P2P3-0001`, `REQ-QUIC-RFC9000-S5P2P3-0003`, `REQ-QUIC-RFC9000-S5P2P3-0005`, `REQ-QUIC-RFC9000-S5P2P3-0006`).

## Requirements Needing Deeper Implementation Work

- `S5P1P2`: CID lifecycle, peer-rotation, retirement policy, and Retire Prior To state management still need a connection-state manager.
- `S5P2`: packet association, key removal, and error-recovery handling still need a packet-processing pipeline.
- `S5P2P1` and `S5P2P2`: client/server packet association and Version Negotiation / handshake decision logic are still missing.
- `S5P2P3`: preferred-address migration orchestration and simple load-balancing safeguards remain out of scope for this slice.

## Tests Run and Results

- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicShortHeaderPacketTests|FullyQualifiedName~QuicFrameCodecPart4Tests|FullyQualifiedName~QuicFrameCodecPart4FuzzTests|FullyQualifiedName~QuicTransportParametersTests|FullyQualifiedName~QuicTransportParametersFuzzTests"`
- Passed: 64
- Failed: 0
- Skipped: 0
- Duration: 176 ms

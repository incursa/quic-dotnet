# RFC 9000 Chunk Reconciliation: `9000-04-connection-ids-basics`

## Scope

Source: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
RFC: `9000`
Section tokens: `S5, S5P1, S5P1P1`

## Status Summary

- implemented and tested: 4
- partially implemented: 1
- tested but implementation mapping unclear: 3
- not implemented: 36
- unclear / needs human review: 0

## Requirements in Scope

### S5

- `REQ-QUIC-RFC9000-S5-0001` - not implemented; This clause requires connection lifecycle behavior that is not represented in the current source set.
- `REQ-QUIC-RFC9000-S5-0002` - not implemented; This clause requires connection lifecycle behavior that is not represented in the current source set.
- `REQ-QUIC-RFC9000-S5-0003` - not implemented; This clause requires connection lifecycle behavior that is not represented in the current source set.
- `REQ-QUIC-RFC9000-S5-0004` - not implemented; This clause requires connection lifecycle behavior that is not represented in the current source set.
- `REQ-QUIC-RFC9000-S5-0005` - not implemented; This clause requires connection lifecycle behavior that is not represented in the current source set.
- `REQ-QUIC-RFC9000-S5-0006` - not implemented; This clause requires connection lifecycle behavior that is not represented in the current source set.
- `REQ-QUIC-RFC9000-S5-0007` - not implemented; This clause requires connection lifecycle behavior that is not represented in the current source set.
- `REQ-QUIC-RFC9000-S5-0008` - partially implemented; The parser and packet model expose connection IDs, but nothing in this chunk uses them to move a connection to a new path.

### S5P1

- `REQ-QUIC-RFC9000-S5P1-0001` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `REQ-QUIC-RFC9000-S5P1-0002` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `REQ-QUIC-RFC9000-S5P1-0003` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `REQ-QUIC-RFC9000-S5P1-0004` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `REQ-QUIC-RFC9000-S5P1-0005` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `RFC9000-S5-1-P4-S1-R01` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `RFC9000-S5-1-P4-S2-R01` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `REQ-QUIC-RFC9000-S5P1-0008` - implemented and tested; The wire-format long-header slice is directly implemented: both CID fields are parsed and preserved.
- `REQ-QUIC-RFC9000-S5P1-0009` - tested but implementation mapping unclear; This is a wire-level remainder-preservation proof, not a full destination-CID parse or length-knowledge proof.
- `REQ-QUIC-RFC9000-S5P1-0010` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `REQ-QUIC-RFC9000-S5P1-0011` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `REQ-QUIC-RFC9000-S5P1-0012` - implemented and tested; The Version Negotiation formatter echoes the client's connection IDs and the parser round-trips the packet view.
- `REQ-QUIC-RFC9000-0215` - tested but implementation mapping unclear; The wire-level acceptance is present, but the requirement depends on routing context that this repo does not model.
- `REQ-QUIC-RFC9000-S5P1-0014` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.
- `REQ-QUIC-RFC9000-0217` - not implemented; This section is mostly connection-state semantics; the repo currently only exposes packet parsing and packet views.

### S5P1P1

- `REQ-QUIC-RFC9000-S5P1P1-0001` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `REQ-QUIC-RFC9000-0219` - tested but implementation mapping unclear; The packet parser preserves source CID bytes; the initial-CID ownership rule is still a connection-state concern.
- `REQ-QUIC-RFC9000-0220` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `REQ-QUIC-RFC9000-0221` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `REQ-QUIC-RFC9000-S5P1P1-0005` - implemented and tested; The NEW_CONNECTION_ID frame codec already parses, formats, and fuzzes the wire representation.
- `REQ-QUIC-RFC9000-0222` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `REQ-QUIC-RFC9000-S5P1P1-0007` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `REQ-QUIC-RFC9000-S5P1P1-0008` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `REQ-QUIC-RFC9000-S5P1P1-0009` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `RFC9000-S5-1-1-P4-S1-R01` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `REQ-QUIC-RFC9000-0229` - implemented and tested; The transport-parameter codec already parses, formats, and fuzzes active_connection_id_limit.
- `RFC9000-S5-1-1-P4-S3-R01` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `RFC9000-S5-1-1-P4-S4-R01` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `RFC9000-S5-1-1-P5-S2-R01` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `RFC9000-S5-1-1-P6-S1-R01` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `RFC9000-S5-1-1-P6-S2-R01` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `RFC9000-S5-1-1-P6-S3-R01` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `RFC9000-S5-1-1-P6-S4-R01` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `RFC9000-S5-1-1-P7-S1-R01` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `REQ-QUIC-RFC9000-0238` - not implemented; This section depends on connection state that the current parser-only implementation does not model.
- `REQ-QUIC-RFC9000-0239` - not implemented; This section depends on connection state that the current parser-only implementation does not model.

## Existing Implementation Evidence

- src/Incursa.Quic/QuicPacketParser.cs:26-96
- src/Incursa.Quic/QuicPacketParsing.cs:11-129
- src/Incursa.Quic/QuicLongHeaderPacket.cs:71-96
- src/Incursa.Quic/QuicVersionNegotiation.cs:61-129
- src/Incursa.Quic/QuicVersionNegotiationPacket.cs:43-84
- src/Incursa.Quic/QuicShortHeaderPacket.cs:55-55
- src/Incursa.Quic/QuicFrameCodec.cs:655-756
- src/Incursa.Quic/QuicTransportParametersCodec.cs:73-454
- src/Incursa.Quic/QuicTransportParameters.cs:51-61

## Existing Test Evidence

- tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:19-437
- tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:53-152
- tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:28-279
- tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:17-187
- tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs:29-133
- tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs:1-420
- tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs:1-220
- tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs:1-460
- tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs:1-220
- tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs:20-79
- tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs:36-60
- tests/Incursa.Quic.Tests/QuicHeaderTestData.cs:15-83

## Generated Inputs Consulted

- specs/generated/quic/import-audit-summary.md
- specs/generated/quic/import-missing-coverage.md
- specs/generated/quic/import-validator-mismatch.md
- specs/generated/quic/quic-existing-work-inventory.md
- specs/generated/quic/implementation-chunk-manifest.md
- specs/generated/quic/9000.assembly-map.json
- specs/requirements/quic/SPEC-QUIC-RFC9000.json

## Old -> New Requirement ID Mappings Applied

- None. No legacy requirement IDs were rewritten in the selected live files for this chunk.
- This pass added the canonical imported `REQ-QUIC-RFC9000-S5P1-0012` trait to the Version Negotiation response formatter tests.

## Gaps Fixed in This Pass

- Added `REQ-QUIC-RFC9000-S5P1-0012` to the Version Negotiation response formatter positive and fuzz tests.
- Reclassified the existing `NEW_CONNECTION_ID` and `active_connection_id_limit` coverage as implemented and tested for `REQ-QUIC-RFC9000-S5P1P1-0005` and `REQ-QUIC-RFC9000-0229`.
- Kept the pass additive: no legacy requirement IDs were replaced, and no out-of-scope short-header or transport-parameter tags were changed.

## Remaining Gaps

- `REQ-QUIC-RFC9000-S5-0001` through `REQ-QUIC-RFC9000-S5-0007`: no connection or handshake state machine exists in this chunk.
- `REQ-QUIC-RFC9000-S5-0008`: long-header CID handling is present, but migration and CID-management behavior are absent.
- `REQ-QUIC-RFC9000-S5P1-0001` through `RFC9000-S5-1-P4-S2-R01`: no CID lifecycle, routing, or peer-selection manager exists in this chunk.
- `REQ-QUIC-RFC9000-S5P1-0009`, `REQ-QUIC-RFC9000-0215`, and `REQ-QUIC-RFC9000-0219` have wire-level evidence, but the repo does not model the connection-state semantics that would make them fully proven.
- `REQ-QUIC-RFC9000-S5P1-0010`, `REQ-QUIC-RFC9000-S5P1-0011`, `REQ-QUIC-RFC9000-S5P1-0014`, and `REQ-QUIC-RFC9000-0217`: no CID lifecycle or routing manager exists.
- `REQ-QUIC-RFC9000-S5P1P1-0001`, `REQ-QUIC-RFC9000-0220` through `REQ-QUIC-RFC9000-0221`, `REQ-QUIC-RFC9000-0222` through `RFC9000-S5-1-1-P4-S1-R01`, and `RFC9000-S5-1-1-P4-S3-R01` through `REQ-QUIC-RFC9000-0239`: no sequence-numbered CID issuance, retirement, or limit-enforcement manager exists in this chunk.

## Requirements Needing Deeper Implementation Work

- `REQ-QUIC-RFC9000-S5-0001` through `REQ-QUIC-RFC9000-S5-0007`
- `REQ-QUIC-RFC9000-S5-0008`
- `REQ-QUIC-RFC9000-S5P1-0001` through `RFC9000-S5-1-P4-S2-R01`
- `REQ-QUIC-RFC9000-S5P1-0010` through `REQ-QUIC-RFC9000-S5P1-0011`
- `REQ-QUIC-RFC9000-S5P1-0014` through `REQ-QUIC-RFC9000-0217`
- `REQ-QUIC-RFC9000-S5P1P1-0001`
- `REQ-QUIC-RFC9000-0220` through `REQ-QUIC-RFC9000-0221`
- `REQ-QUIC-RFC9000-0222` through `RFC9000-S5-1-1-P4-S1-R01`
- `RFC9000-S5-1-1-P4-S3-R01` through `REQ-QUIC-RFC9000-0239`

## Tests Run and Results

- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicVersionNegotiationTests|FullyQualifiedName~QuicFrameCodecPart4Tests|FullyQualifiedName~QuicFrameCodecPart4FuzzTests|FullyQualifiedName~QuicTransportParametersTests|FullyQualifiedName~QuicTransportParametersFuzzTests"`
- Passed: 97
- Failed: 0
- Skipped: 0
- Duration: 468 ms

# RFC 9001 Chunk Reconciliation: `9001-02-security-and-registry`

## Scope

Source: `./specs/requirements/quic/SPEC-QUIC-RFC9001.json`
RFC: `9001`
Section tokens: `S6`, `S7`, `S8`, `S9`, `S10`

## Status Summary

- implemented and tested: 6
- partially implemented: 1
- blocked: 9
- deferred: 2
- silent gaps: 0

## Requirements in Scope

### S6

- `REQ-QUIC-RFC9001-S6-0001` Allow key update after handshake confirmation - `blocked`
- `REQ-QUIC-RFC9001-S6-0002` Identify packet protection keys with Key Phase - `implemented and tested`
- `REQ-QUIC-RFC9001-S6-0003` Initialize Key Phase to zero - `blocked`
- `REQ-QUIC-RFC9001-S6-0004` Toggle Key Phase on each update - `implemented and tested`
- `REQ-QUIC-RFC9001-S6-0005` Let Key Phase detect key changes - `partially implemented`
- `REQ-QUIC-RFC9001-S6-0006` Update keys when Key Phase changes - `blocked`
- `REQ-QUIC-RFC9001-S6-0007` Decrypt the packet with the changed Key Phase - `blocked`
- `REQ-QUIC-RFC9001-S6-0008` Update both endpoints on key update - `blocked`
- `REQ-QUIC-RFC9001-S6-0009` Prohibit TLS KeyUpdate messages - `blocked`
- `REQ-QUIC-RFC9001-S6-0010` Treat TLS KeyUpdate as a connection error - `blocked`

### S7

- `REQ-QUIC-RFC9001-S7-0001` Use caution with unauthenticated Initial data - `deferred`
- `REQ-QUIC-RFC9001-S7-0002` Fail on Handshake tampering - `blocked`

### S8

- `REQ-QUIC-RFC9001-S8-0001` Carry QUIC transport parameters - `implemented and tested`
- `REQ-QUIC-RFC9001-S8-0002` Authenticate QUIC transport parameters - `blocked`

### S9

- `REQ-QUIC-RFC9001-S9-0001` Apply TLS security considerations to QUIC - `deferred`

### S10

- `REQ-QUIC-RFC9001-S10-0001` Register quic_transport_parameters at codepoint 57 - `implemented and tested`
- `REQ-QUIC-RFC9001-S10-0002` Mark Recommended as Yes - `implemented and tested`
- `REQ-QUIC-RFC9001-S10-0003` Include CH and EE in TLS 1.3 column - `implemented and tested`

## Existing Implementation Evidence

- `src/Incursa.Quic/QuicShortHeaderPacket.cs`
- `src/Incursa.Quic/QuicPacketParser.cs`
- `src/Incursa.Quic/QuicTransportParametersCodec.cs`
- `src/Incursa.Quic/QuicTransportParameters.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`

## Existing Test Evidence

- `tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs`
- `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs`
- `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`
- `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S6-0004.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S6-0005.cs`

## Generated Inputs Consulted

- `specs/generated/quic/quic-requirement-coverage-triage.md`
- `specs/generated/quic/implementation-chunk-manifest.md`
- `specs/generated/quic/import-audit-summary.md`
- `specs/generated/quic/import-missing-coverage.md`
- `specs/generated/quic/import-validator-mismatch.md`

## Verification

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
  - `327 passed, 0 failed, 0 skipped`
- `dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicTransportParametersBenchmarks*"`
  - `2 benchmarks executed successfully in Dry mode`

## Remaining Gaps

- `REQ-QUIC-RFC9001-S6-0005` still needs edge proof.
- The blocked S6 items remain blocked until handshake-confirmation, key-update, or TLS message-processing support exists.
- `REQ-QUIC-RFC9001-S7-0001` and `REQ-QUIC-RFC9001-S9-0001` remain deferred as policy and document-scope items.

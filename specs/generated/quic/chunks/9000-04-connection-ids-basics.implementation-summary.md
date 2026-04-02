# RFC 9000 Chunk Implementation Summary: `9000-04-connection-ids-basics`

## Scope

Source: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
RFC: `9000`
Section tokens: `S5, S5P1, S5P1P1`

## Requirements Completed

- `REQ-QUIC-RFC9000-S5P1-0008`: long-header CID fields are parsed and preserved.
- `REQ-QUIC-RFC9000-S5P1-0012`: Version Negotiation formatting/parsing echoes connection IDs and supported versions.
- `REQ-QUIC-RFC9000-S5P1P1-0005`: `NEW_CONNECTION_ID` frame wire encoding/decoding is covered.
- `REQ-QUIC-RFC9000-S5P1P1-0011`: `active_connection_id_limit` transport-parameter encoding/decoding is covered.

## Files Changed

- `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs`
- `specs/generated/quic/chunks/9000-04-connection-ids-basics.implementation-summary.md`
- `specs/generated/quic/chunks/9000-04-connection-ids-basics.implementation-summary.json`

## Tests Added or Updated

- `REQ-QUIC-RFC9000-S5P1-0013`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:TryParseLongHeader_AllowsZeroLengthConnectionIds`
  - Supporting coverage remains in `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:TryParseLongHeader_RoundTripsHeaderFields` and `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:Fuzz_LongHeaderParsing_RoundTripsValidInputsAndRejectsTruncation`.
  - The new test documents zero-length CID acceptance explicitly, but the routing precondition is still blocked by missing stateful connection logic.

## Tests Run and Results

- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicVersionNegotiationTests|FullyQualifiedName~QuicFrameCodecPart4Tests|FullyQualifiedName~QuicFrameCodecPart4FuzzTests|FullyQualifiedName~QuicTransportParametersTests|FullyQualifiedName~QuicTransportParametersFuzzTests"`
- Passed: 98
- Failed: 0
- Skipped: 0
- Duration: 177 ms

## Remaining Open Requirements in Scope

- `REQ-QUIC-RFC9000-S5-0001` through `REQ-QUIC-RFC9000-S5-0007`: blocked by the absence of connection or handshake state machine behavior in this chunk.
- `REQ-QUIC-RFC9000-S5-0008`: blocked by missing migration and path-state logic.
- `REQ-QUIC-RFC9000-S5P1-0001` through `REQ-QUIC-RFC9000-S5P1-0007`, `REQ-QUIC-RFC9000-S5P1-0010`, `REQ-QUIC-RFC9000-S5P1-0011`, `REQ-QUIC-RFC9000-S5P1-0014`, `REQ-QUIC-RFC9000-S5P1-0015`: blocked by missing CID lifecycle, routing, and peer-selection managers.
- `REQ-QUIC-RFC9000-S5P1-0009`: blocked because the short-header parser preserves the remainder but does not model the destination-CID boundary or length.
- `REQ-QUIC-RFC9000-S5P1-0013`: blocked because zero-length CIDs are wire-accepted, but the routing precondition is not modeled.
- `REQ-QUIC-RFC9000-S5P1P1-0001`, `REQ-QUIC-RFC9000-S5P1P1-0003` through `REQ-QUIC-RFC9000-S5P1P1-0004`, `REQ-QUIC-RFC9000-S5P1P1-0006` through `REQ-QUIC-RFC9000-S5P1P1-0021`: blocked because the repo does not have sequence-numbered CID issuance, retirement, or limit-enforcement state.
- `REQ-QUIC-RFC9000-S5P1P1-0002`: blocked because the parser preserves source CID bytes, but there is no handshake sender or stateful connection logic proving initial-CID ownership.

## Risks or Follow-up Notes

- The repo still lacks a CID lifecycle and migration manager, so the stateful parts of Section 5.1.1 remain out of scope.
- `S5P1-0013` now has explicit zero-length CID test evidence, but routing semantics are still blocked.
- The work in this pass stayed narrow: one explicit long-header zero-length CID proof test and trace-summary updates.

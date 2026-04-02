# RFC 9000 Chunk Closeout: `9000-04-connection-ids-basics`

## Scope

Source: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
RFC: `9000`
Section tokens: `S5, S5P1, S5P1P1`

## Audit Result

- No stale requirement IDs remain in the scoped tests.
- No requirement-tagged source refs were found under `src/Incursa.Quic`.
- Current direct test traits use the imported IDs `REQ-QUIC-RFC9000-S5P1-0008`, `REQ-QUIC-RFC9000-S5P1-0012`, `REQ-QUIC-RFC9000-S5P1-0013`, `REQ-QUIC-RFC9000-S5P1P1-0005`, and `REQ-QUIC-RFC9000-S5P1P1-0011`.

## Requirements Completed

- `REQ-QUIC-RFC9000-S5P1-0008`: long-header CID fields are parsed and preserved; the trace coverage was already in place from the prior pass and remains valid.
- `REQ-QUIC-RFC9000-S5P1-0012`: Version Negotiation echoes the client's connection IDs; the formatter test plus parser/property/fuzz coverage now carry the imported ID.
- `REQ-QUIC-RFC9000-S5P1P1-0005`: additional connection IDs are communicated with `NEW_CONNECTION_ID` frames; the existing frame codec tests and fuzz coverage are now tagged with the imported ID.
- `REQ-QUIC-RFC9000-S5P1P1-0011`: endpoints advertise `active_connection_id_limit` with transport parameters; the coverage now includes a client-role round-trip test in addition to the existing server-role and fuzz coverage.

## Files Changed

- Prior trace pass carried forward:
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`
  - `tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs`
  - `tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs`
  - `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`
  - `tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs`
- This pass:
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs`
- Generated reports:
  - `specs/generated/quic/chunks/9000-04-connection-ids-basics.implementation-summary.md`
  - `specs/generated/quic/chunks/9000-04-connection-ids-basics.implementation-summary.json`

## Tests Added or Updated

- `REQ-QUIC-RFC9000-S5P1-0008`
  - `QuicLongHeaderPacketTests.TryParseLongHeader_RoundTripsLengthEncodedConnectionIdsAndPayload`
  - `QuicHeaderPropertyTests.TryParseLongHeader_RoundTripsHeaderFields`
  - `QuicHeaderFuzzTests.Fuzz_LongHeaderParsing_RoundTripsValidInputsAndRejectsTruncation`
- `REQ-QUIC-RFC9000-S5P1-0012`
  - `QuicVersionNegotiationTests.TryFormatVersionNegotiationResponse_FormatsEchoedConnectionIdsAndSupportedVersions`
  - `QuicVersionNegotiationPacketTests.TryParseVersionNegotiation_ExposesSupportedVersions`
  - `QuicHeaderPropertyTests.TryParseVersionNegotiation_RoundTripsSupportedVersions`
  - `QuicHeaderFuzzTests.Fuzz_VersionNegotiationParsing_RoundTripsValidInputsAndRejectsTruncation`
  - `QuicHeaderFuzzTests.Fuzz_VersionNegotiationFormatting_RoundTripsFormattedResponses`
- `REQ-QUIC-RFC9000-S5P1-0013`
  - `QuicLongHeaderPacketTests.TryParseLongHeader_AllowsZeroLengthConnectionIds`
  - `QuicHeaderPropertyTests.TryParseLongHeader_RoundTripsHeaderFields`
  - `QuicHeaderFuzzTests.Fuzz_LongHeaderParsing_RoundTripsValidInputsAndRejectsTruncation`
- `REQ-QUIC-RFC9000-S5P1P1-0005`
  - `QuicFrameCodecPart4Tests.TryParseNewConnectionIdFrame_ParsesAndFormatsTheEncodedFields`
  - `QuicFrameCodecPart4Tests.TryParseNewConnectionIdFrame_AcceptsBoundaryConnectionIdLengths`
  - `QuicFrameCodecPart4FuzzTests.Fuzz_FrameCodecPart4_RoundTripsRepresentativeFrameShapesAndRejectsTruncation`
- `REQ-QUIC-RFC9000-S5P1P1-0011`
  - `QuicTransportParametersTests.TryFormatTransportParameters_WritesExactTupleSequence`
  - `QuicTransportParametersTests.TryFormatTransportParameters_EmitsActiveConnectionIdLimitWhenSendingAsClient`
  - `QuicTransportParametersTests.TryParseTransportParameters_RoundTripsKnownFieldsAndPreferredAddress`
  - `QuicTransportParametersFuzzTests.Fuzz_TransportParameters_RoundTripsRepresentativeValuesAndRejectsTruncation`
- `REQ-QUIC-RFC9000-S5P1-0012`
  - `QuicVersionNegotiationPacketTests.TryParseVersionNegotiation_ExposesSupportedVersions`
  - `QuicHeaderPropertyTests.TryParseVersionNegotiation_RoundTripsSupportedVersions`
  - `QuicHeaderFuzzTests.Fuzz_VersionNegotiationParsing_RoundTripsValidInputsAndRejectsTruncation`

## Tests Run and Results

- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicFrameCodecPart4Tests|FullyQualifiedName~QuicFrameCodecPart4FuzzTests|FullyQualifiedName~QuicTransportParametersTests|FullyQualifiedName~QuicTransportParametersFuzzTests"`
- Passed: 98
- Failed: 0
- Skipped: 0
- Duration: 177 ms

## Remaining Open Requirements in Scope

- `REQ-QUIC-RFC9000-S5-0001` through `REQ-QUIC-RFC9000-S5-0007`
- `REQ-QUIC-RFC9000-S5-0008`
- `REQ-QUIC-RFC9000-S5P1-0001` through `REQ-QUIC-RFC9000-S5P1-0007`
- `REQ-QUIC-RFC9000-S5P1-0009` through `REQ-QUIC-RFC9000-S5P1-0010`
- `REQ-QUIC-RFC9000-S5P1-0014` through `REQ-QUIC-RFC9000-S5P1-0015`
- `REQ-QUIC-RFC9000-S5P1P1-0001` through `REQ-QUIC-RFC9000-S5P1P1-0004`
- `REQ-QUIC-RFC9000-S5P1P1-0006` through `REQ-QUIC-RFC9000-S5P1P1-0010`
- `REQ-QUIC-RFC9000-S5P1P1-0012` through `REQ-QUIC-RFC9000-S5P1P1-0021`
- `REQ-QUIC-RFC9000-S5P1-0013` remains blocked by the lack of routing-state modeling, even though the zero-length CID case now has an explicit proof test.
- `REQ-QUIC-RFC9000-S5P1P1-0002` remains wire-level evidence only; the repo still does not model the connection-state semantics that would close the initial-CID ownership rule.

## Risks / Follow-up Notes

- The repo still lacks a CID lifecycle / migration manager, so the stateful parts of Section 5.1.1 remain out of scope.
- The imported trace coverage is now clean for the wire-format pieces, but endpoint behavior such as CID issuance, retirement, replenishment, and limit enforcement still needs a separate implementation slice.
- The zero-length CID proof is intentionally narrow: it covers wire acceptance, not the routing precondition from the RFC.

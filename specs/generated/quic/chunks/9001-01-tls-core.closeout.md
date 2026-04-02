# RFC 9001 Chunk Closeout: `9001-01-tls-core`

## Scope

- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9001.json`
- RFC: `9001`
- Section tokens: `S2`, `S3`, `S4`, `S5`
- Reconciliation artifact reviewed: `./specs/generated/quic/chunks/9001-01-tls-core.reconciliation.json`
- Implementation summary reviewed: `./specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.json`

## Audit Result

- Audit result: `clean_with_explicit_blockers`
- No stale requirement IDs remain in scope.
- No requirement-tagged source refs were found under `src/Incursa.Quic`.
- Current tests reference only the imported RFC 9001 IDs in scope.
- No old->new requirement ID rewrites were needed.
- The remaining open requirements all carry explicit blocker or deferred notes; there are no silent gaps.

## Requirements In Scope

- `S2`: 1 requirement
- `S3`: 12 requirements
- `S4`: 11 requirements
- `S5`: 10 requirements
- Total in scope: **34**
- Covered: **4**
- Blocked / deferred: **30**
- Partial: **0**
- Needs review: **0**

## Requirements Completed

- `REQ-QUIC-RFC9001-S3-0012` Send data as QUIC frames.
  - Evidence files: `src/Incursa.Quic/QuicFrameCodec.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`, `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`, `benchmarks/QuicFrameCodecBenchmarks.cs`, `benchmarks/README.md`.
  - Test files: `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs::TryParseStreamFrame_ParsesOffsetsLengthsAndPayloadBytes`, `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs::TryParseStreamFrame_UsesTheRemainderWhenLengthIsAbsent`, `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs::TryFormatStreamFrame_RejectsInvalidTypesAndOffsetMismatches`, `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs::TryParseStreamFrame_PreservesZeroLengthPayloadOffsets`, `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs::TryParseStreamFrame_RoundTripsRepresentableStreamShapes`, `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs::Fuzz_StreamParsing_RoundTripsRepresentativeFramesAndRejectsTruncation`.
- `REQ-QUIC-RFC9001-S4-0001` Carry handshake data in CRYPTO frames.
  - Evidence files: `src/Incursa.Quic/QuicFrameCodec.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`.
  - Test files: `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs::TryParseCryptoFrame_ParsesAndFormatsAllFields`, `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs::Fuzz_FrameCodec_RoundTripsRepresentativeFrameShapesAndRejectsTruncation`.
- `REQ-QUIC-RFC9001-S4-0002` Define CRYPTO frame boundaries.
  - Evidence files: `src/Incursa.Quic/QuicFrameCodec.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`.
  - Test files: `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs::TryParseCryptoFrame_ParsesAndFormatsAllFields`, `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs::TryParseCryptoFrame_AcceptsFramesThatExactlyReachTheStreamCeiling`, `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs::TryParseCryptoFrame_RejectsFramesThatExceedTheStreamCeiling`, `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs::TryFormatCryptoFrame_RejectsFramesThatExceedTheStreamCeiling`, `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs::Fuzz_FrameCodec_RoundTripsRepresentativeFrameShapesAndRejectsTruncation`.
- `REQ-QUIC-RFC9001-S5-0003` Leave Version Negotiation packets unprotected.
  - Evidence files: `src/Incursa.Quic/QuicVersionNegotiation.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
  - Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs::TryFormatVersionNegotiationResponse_FormatsEchoedConnectionIdsAndSupportedVersions`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs::Fuzz_VersionNegotiationFormatting_RoundTripsFormattedResponses`.

## Remaining Open Requirements

- `REQ-QUIC-RFC9001-S2-0001`: intentionally deferred; document-level BCP 14 interpretation rule with no live code or test artifact expected.
- `REQ-QUIC-RFC9001-S3-0001` through `REQ-QUIC-RFC9001-S3-0011`: blocked by the absence of a TLS handshake, packet-protection, and QUIC/TLS delivery surface.
- `REQ-QUIC-RFC9001-S4-0003` through `REQ-QUIC-RFC9001-S4-0011`: blocked by the absence of handshake transport and encryption-level plumbing needed to package CRYPTO frames end-to-end.
- `REQ-QUIC-RFC9001-S5-0001`, `REQ-QUIC-RFC9001-S5-0002`, and `REQ-QUIC-RFC9001-S5-0004` through `REQ-QUIC-RFC9001-S5-0010`: blocked by the absence of packet-protection and key-derivation surfaces.

## Reference Audit

- Source roots checked: `src/Incursa.Quic`
- Test roots checked: `tests/Incursa.Quic.Tests`
- In-scope source requirement refs found: none
- In-scope test requirement refs found: `REQ-QUIC-RFC9001-S3-0012`, `REQ-QUIC-RFC9001-S4-0001`, `REQ-QUIC-RFC9001-S4-0002`, `REQ-QUIC-RFC9001-S5-0003`
- Stale or wrong refs found: none
- Current in-scope test files: `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`

## Tests Run And Results

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
  - Result: `Passed`
  - Summary: `204 passed, 0 failed, 0 skipped`

## Benchmark Evidence

- `dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"`
  - Result: `Passed`
  - Summary: `3 benchmarks executed successfully in Dry mode`

## Risks / Follow-up Notes

- The remaining RFC 9001 work is still blocked by missing TLS handshake, packet-protection, and key-update surfaces outside this chunk.
- This audit validates trace consistency for the completed chunk items; it does not add new protocol behavior beyond the existing implementation summary.
- `REQ-QUIC-RFC9001-S2-0001` remains a document-level rule and is intentionally deferred.

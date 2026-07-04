# 9000-18-ack-generation Closeout

## Audit Result
- `clean_with_explicit_blockers`
- In-scope requirements: 54 total, 36 implemented and tested, 14 blocked with explicit notes, 4 deferred with explicit notes.
- Stale or wrong requirement IDs: none found.
- `src/` contains no in-scope requirement refs; all trace refs are in `tests/` and use the correct IDs.
- No reconciliation artifact existed for this chunk; the implementation summary was treated as the source of truth.

## Requirements Completed
- `S13P1`: `REQ-QUIC-RFC9000-S13P1-0003`
- `S13P2`: `REQ-QUIC-RFC9000-0753`, `REQ-QUIC-RFC9000-S13P2-0002`, `REQ-QUIC-RFC9000-S13P2-0003`, `RFC9000-S13-2-P2-R01`
- `S13P2P1`: `REQ-QUIC-RFC9000-S13P2P1-0001`, `RFC9000-S13-2-1-P1-R01`, `RFC9000-S13-2-1-P2-R02`, `RFC9000-S13-2-1-P2-R01`, `RFC9000-S13-2-1-P3-R01`, `REQ-QUIC-RFC9000-S13P2P1-0007`, `REQ-QUIC-RFC9000-S13P2P1-0008`, `RFC9000-S13-2-1-P5-S1-R01`, `RFC9000-S13-2-1-P5-S2-R01`, `REQ-QUIC-RFC9000-S13P2P1-0013`, `REQ-QUIC-RFC9000-1322`
- `S13P2P2`: `REQ-QUIC-RFC9000-S13P2P2-0001`, `RFC9000-S13-2-2-P4-S1-R01`, `RFC9000-S13-2-2-P5-S1-R01`
- `S13P2P3`: `REQ-QUIC-RFC9000-S13P2P3-0001`, `REQ-QUIC-RFC9000-13230`, `REQ-QUIC-RFC9000-S13P2P3-0003`, `REQ-QUIC-RFC9000-13233`, `REQ-QUIC-RFC9000-13235`, `REQ-QUIC-RFC9000-S13P2P3-0008`, `REQ-QUIC-RFC9000-13236`, `RFC9000-S13-2-3-P5-S1-R01`, `REQ-QUIC-RFC9000-S13P2P3-0011`, `RFC9000-S13-2-3-P7-S1-R01`
- `S13P2P5`: `REQ-QUIC-RFC9000-S13P2P5-0001`, `REQ-QUIC-RFC9000-S13P2P5-0002`, `RFC9000-S13-2-5-P2-S2-R01`, `RFC9000-S13-2-5-P2-S3-R01`, `RFC9000-S13-2-5-P3-S1-R01`
- `S13P2P6`: `RFC9000-S13-2-6-P1-S1-R01`, `RFC9000-S13-2-6-P1-S2-R01`

## Files Changed
- [QuicPacketNumberSpace.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPacketNumberSpace.cs)
- [QuicAckGenerationState.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicAckGenerationState.cs)
- [QuicCongestionControlState.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicCongestionControlState.cs)
- [PublicAPI.Unshipped.txt](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt)
- [QuicAckGenerationStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs)
- [QuicFrameCodecTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs)
- [QuicFrameCodecFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs)
- [RFC9000-S13-2-5-P2-S3-R01.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/RFC9000-S13-2-5-P2-S3-R01.cs)
- [9000-18-ack-generation.implementation-summary.md](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-18-ack-generation.implementation-summary.md)
- [9000-18-ack-generation.implementation-summary.json](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-18-ack-generation.implementation-summary.json)

## Tests Added Or Updated
- [QuicAckGenerationStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs): added coverage for `TryBuildAckFrame_RoundsTripProcessedPacketsAndReportsAckDelay`, `ShouldDelayAckUntilSecondAckElicitingPacketOrMaxAckDelay`, `ShouldSendAckImmediately_ForInitialAndHandshakePackets`, `ShouldSendAckImmediately_ForOutOfOrderAndCePackets`, `CanSendOnlyOneAckOnlyPacketPerAckElicitingPacket`, `PacketNumberSpaces_AreTrackedIndependently`, `TryBuildAckFrame_TrimsOldestRangesWhenLimitReached`, and `TryBuildAckFrame_UsesEcnCountsAndReportsMeasuredDelayWhenDelayed`.
- [QuicFrameCodecTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs): added ACK-frame codec round-trip coverage for `TryParseAckFrame_RoundTripsRangesAndEcnCounts`.
- [QuicFrameCodecFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs): added fuzz coverage for `Fuzz_FrameCodec_RoundTripsRepresentativeFrameShapesAndRejectsTruncation`.
- [RFC9000-S13-2-5-P2-S3-R01.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/RFC9000-S13-2-5-P2-S3-R01.cs): added coverage for `TryBuildAckFrame_IncludesBufferingDelayFromUnavailableDecryptionKeys` and `TryBuildAckFrame_DoesNotInventBufferingDelayWhenNoneWasRecorded`.

## Tests Run And Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicAckGenerationStateTests|FullyQualifiedName~QuicFrameCodecTests|FullyQualifiedName~QuicFrameCodecFuzzTests"` -> `18 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj` -> `249 passed, 0 failed, 0 skipped`

## Remaining Open Requirements In Scope
### Deferred
- `REQ-QUIC-RFC9000-S13P2P3-0006`
- `REQ-QUIC-RFC9000-S13P2P3-0013`
- `REQ-QUIC-RFC9000-S13P2P4-0001`
- `REQ-QUIC-RFC9000-S13P2P6-0004`

These are explanatory or section-marker clauses without a separate executable path in the current slice.

### Blocked
- `REQ-QUIC-RFC9000-S13-0001`
- `RFC9000-S13-P2-S2-R01`
- `RFC9000-S13-P2-S3-R01`
- `REQ-QUIC-RFC9000-S13-0004`
- `REQ-QUIC-RFC9000-S13-0005`
- `REQ-QUIC-RFC9000-0749`
- `REQ-QUIC-RFC9000-S13P1-0002`
- `RFC9000-S13-1-P3-R01`
- `REQ-QUIC-RFC9000-S13P2P1-0003`
- `RFC9000-S13-2-1-P5-S1-R02`
- `RFC9000-S13-2-1-P6-S1-R01`
- `REQ-QUIC-RFC9000-13234`
- `REQ-QUIC-RFC9000-S13P2P6-0003`
- `RFC9000-S13-2-7-P1-S3-R01`

These depend on packet assembly, send-path batching, recovery timers, peer-ACK handling, or carrier-selection surfaces that are not present yet.

## Reference Audit
- [src/Incursa.Quic/QuicAckGenerationState.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicAckGenerationState.cs): no in-scope requirement refs.
- [src/Incursa.Quic/QuicPacketNumberSpace.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPacketNumberSpace.cs): no in-scope requirement refs.
- [src/Incursa.Quic/PublicAPI.Unshipped.txt](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt): no in-scope requirement refs.
- [tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs): only correct in-scope requirement IDs.
- [tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs): only correct in-scope requirement IDs.
- [tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs): only correct in-scope requirement IDs.
- [tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S13P2P1-0007.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S13P2P1-0007.cs): only correct in-scope requirement IDs.

## Risks Or Follow-Up Notes
- The chunk is internally consistent, but the remaining 19 open requirements still depend on missing packet-composition, send-path batching, recovery timer, peer-ACK, decryption, and carrier-selection surfaces.
- The requirement-home proof for `RFC9000-S13-2-5-P2-S3-R01` now closes the decryption-key buffering-delay gap and keeps the remaining blocked set focused on packet assembly, timing, peer-ACK, and carrier-selection work.
- No stale IDs or silent gaps were found in the scoped code or tests.

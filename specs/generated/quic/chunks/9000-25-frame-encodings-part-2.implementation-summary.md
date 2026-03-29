# 9000-25-frame-encodings-part-2 Implementation Summary

## Requirements Completed

- `REQ-QUIC-RFC9000-S19P1-0001`
- `REQ-QUIC-RFC9000-S19P1-0004`
- `REQ-QUIC-RFC9000-S19P1-0005`
- `REQ-QUIC-RFC9000-S19P1-0006`
- `REQ-QUIC-RFC9000-S19P2-0002`
- `REQ-QUIC-RFC9000-S19P2-0003`
- `REQ-QUIC-RFC9000-S19P3-0001`
- `REQ-QUIC-RFC9000-S19P3-0002`
- `REQ-QUIC-RFC9000-S19P3-0003`
- `REQ-QUIC-RFC9000-S19P3-0009`
- `REQ-QUIC-RFC9000-S19P3-0010`
- `REQ-QUIC-RFC9000-S19P3-0011`
- `REQ-QUIC-RFC9000-S19P3-0012`
- `REQ-QUIC-RFC9000-S19P3-0013`
- `REQ-QUIC-RFC9000-S19P3-0014`
- `REQ-QUIC-RFC9000-S19P3-0015`
- `REQ-QUIC-RFC9000-S19P3-0016`
- `REQ-QUIC-RFC9000-S19P3-0017`
- `REQ-QUIC-RFC9000-S19P3-0018`
- `REQ-QUIC-RFC9000-S19P3-0019`
- `REQ-QUIC-RFC9000-S19P3-0020`
- `REQ-QUIC-RFC9000-S19P3P1-0001`
- `REQ-QUIC-RFC9000-S19P3P1-0002`
- `REQ-QUIC-RFC9000-S19P3P1-0003`
- `REQ-QUIC-RFC9000-S19P3P1-0004`
- `REQ-QUIC-RFC9000-S19P3P1-0005`
- `REQ-QUIC-RFC9000-S19P3P1-0006`
- `REQ-QUIC-RFC9000-S19P3P1-0007`
- `REQ-QUIC-RFC9000-S19P3P1-0008`
- `REQ-QUIC-RFC9000-S19P3P1-0009`
- `REQ-QUIC-RFC9000-S19P3P1-0010`
- `REQ-QUIC-RFC9000-S19P3P2-0001`
- `REQ-QUIC-RFC9000-S19P3P2-0002`
- `REQ-QUIC-RFC9000-S19P3P2-0003`
- `REQ-QUIC-RFC9000-S19P3P2-0004`
- `REQ-QUIC-RFC9000-S19P3P2-0005`
- `REQ-QUIC-RFC9000-S19P3P2-0006`
- `REQ-QUIC-RFC9000-S19P3P2-0007`
- `REQ-QUIC-RFC9000-S19P4-0004`
- `REQ-QUIC-RFC9000-S19P4-0005`
- `REQ-QUIC-RFC9000-S19P4-0006`
- `REQ-QUIC-RFC9000-S19P4-0007`
- `REQ-QUIC-RFC9000-S19P4-0008`
- `REQ-QUIC-RFC9000-S19P4-0009`
- `REQ-QUIC-RFC9000-S19P4-0010`
- `REQ-QUIC-RFC9000-S19P4-0011`
- `REQ-QUIC-RFC9000-S19P5-0005`
- `REQ-QUIC-RFC9000-S19P5-0006`
- `REQ-QUIC-RFC9000-S19P5-0007`
- `REQ-QUIC-RFC9000-S19P5-0008`
- `REQ-QUIC-RFC9000-S19P5-0009`
- `REQ-QUIC-RFC9000-S19P5-0010`

These 52 requirements are covered by the frame codec, the frame model types, and the roundtrip/negative tests in `QuicFrameCodecTests` and `QuicFrameCodecFuzzTests`.

## Files Changed

- `src/Incursa.Quic/QuicAckFrame.cs`
- `src/Incursa.Quic/QuicAckRange.cs`
- `src/Incursa.Quic/QuicEcnCounts.cs`
- `src/Incursa.Quic/QuicFrameCodec.cs`
- `src/Incursa.Quic/QuicResetStreamFrame.cs`
- `src/Incursa.Quic/QuicStopSendingFrame.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicFrameTestData.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`
- `specs/generated/quic/chunks/9000-25-frame-encodings-part-2.implementation-summary.md`
- `specs/generated/quic/chunks/9000-25-frame-encodings-part-2.implementation-summary.json`

## Tests Added Or Updated

- `TryParsePaddingFrame_ParsesAndFormatsTheTypeOnlyFrame`
- `TryParsePaddingAndPingFrame_RejectsEmptyAndMismatchedTypes`
- `TryParsePingFrame_ParsesAndFormatsTheTypeOnlyFrame`
- `TryParseAckFrame_RoundTripsRangesAndEcnCounts`
- `TryParseAckFrame_RejectsTruncatedAndInvalidRangeLayouts`
- `TryParseResetStreamFrame_ParsesAndFormatsAllFields`
- `TryParseResetStreamFrame_RejectsTruncatedInputs`
- `TryParseStopSendingFrame_ParsesAndFormatsAllFields`
- `TryParseStopSendingFrame_RejectsTruncatedInputs`
- `Fuzz_FrameCodec_RoundTripsRepresentativeFrameShapesAndRejectsTruncation`

## Tests Run And Results

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --logger "console;verbosity=minimal"`
- Result: Passed
- Summary: 155 passed, 0 failed, 0 skipped

## Remaining Open Requirements In Scope

- `REQ-QUIC-RFC9000-S19P1-0002`
- `REQ-QUIC-RFC9000-S19P1-0003`
- `REQ-QUIC-RFC9000-S19P2-0001`
- `REQ-QUIC-RFC9000-S19P2-0004`
- `REQ-QUIC-RFC9000-S19P3-0004`
- `REQ-QUIC-RFC9000-S19P3-0005`
- `REQ-QUIC-RFC9000-S19P3-0006`
- `REQ-QUIC-RFC9000-S19P3-0007`
- `REQ-QUIC-RFC9000-S19P3-0008`
- `REQ-QUIC-RFC9000-S19P4-0001`
- `REQ-QUIC-RFC9000-S19P4-0002`
- `REQ-QUIC-RFC9000-S19P4-0003`
- `REQ-QUIC-RFC9000-S19P5-0001`
- `REQ-QUIC-RFC9000-S19P5-0002`
- `REQ-QUIC-RFC9000-S19P5-0003`
- `REQ-QUIC-RFC9000-S19P5-0004`

## Risks Or Follow-Up Notes

- The remaining open requirements are all higher-layer semantics: packet assembly, connection liveness, ACK state retention, congestion-state use of ECN, and stream-state error propagation. Those are blocked by layers that this codec-only slice does not own.
- The frame codec and tests prove wire encoding/decoding, but they do not yet provide a frame-specific benchmark suite. That is a follow-up item for the `benchmarks` tree.
- No old requirement IDs were found in the in-scope frame sources or tests, so no ID rewrites were needed in this chunk.

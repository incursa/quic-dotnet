# 9000-03-flow-control Implementation Summary

## Requirements Completed
- `REQ-QUIC-RFC9000-S4-0004`
- `REQ-QUIC-RFC9000-S4-0005`
- `REQ-QUIC-RFC9000-S4P1-0005` through `REQ-QUIC-RFC9000-S4P1-0009`
- `REQ-QUIC-RFC9000-S4P1-0014`
- `REQ-QUIC-RFC9000-S4P5-0002` through `REQ-QUIC-RFC9000-S4P5-0003`
- `REQ-QUIC-RFC9000-S4P6-0003` through `REQ-QUIC-RFC9000-S4P6-0007`
- `REQ-QUIC-RFC9000-S4P6-0012`

## Files Changed
- `benchmarks/QuicTransportParametersBenchmarks.cs`
- `benchmarks/README.md`
- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `src/Incursa.Quic/QuicTransportParameters.cs`
- `src/Incursa.Quic/QuicTransportParametersCodec.cs`
- `tests/Incursa.Quic.Tests/QuicCryptoBufferTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`
- `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`

## Tests Added or Updated
- Updated `QuicTransportParametersTests.TryFormatTransportParameters_WritesExactTupleSequence`.
- Updated `QuicTransportParametersTests.TryParseTransportParameters_RoundTripsKnownFieldsAndPreferredAddress`.
- Added `QuicTransportParametersTests.TryParseAndFormatTransportParameters_RejectsInitialMaxStreamsAboveTheEncodingLimit`.
- Updated `QuicTransportParametersFuzzTests.Fuzz_TransportParameters_RoundTripsRepresentativeValuesAndRejectsTruncation`.
- Updated `QuicFrameCodecPart3Tests.TryParseCryptoFrame_ParsesAndFormatsAllFields`.
- Updated `QuicFrameCodecPart3Tests.TryParseCryptoFrame_AcceptsFramesThatExactlyReachTheStreamCeiling`.
- Updated `QuicFrameCodecPart3Tests.TryParseCryptoFrame_RejectsFramesThatExceedTheStreamCeiling`.
- Updated `QuicFrameCodecPart3Tests.TryFormatCryptoFrame_RejectsFramesThatExceedTheStreamCeiling`.
- Updated `QuicFrameCodecPart3Tests.TryParseMaxDataFrame_ParsesAndFormatsTheMaximumDataField`.
- Updated `QuicFrameCodecPart3Tests.TryParseMaxStreamDataFrame_ParsesAndFormatsTheFrameFields`.
- Updated `QuicFrameCodecPart3Tests.TryParseMaxStreamsFrame_ParsesAndFormatsBidirectionalAndUnidirectionalVariants`.
- Updated `QuicFrameCodecPart3Tests.TryParseMaxStreamsFrame_RejectsValuesAboveTheEncodingLimit`.
- Updated `QuicFrameCodecPart4Tests.TryParseDataBlockedFrame_ParsesAndFormatsTheMaximumDataField`.
- Updated `QuicFrameCodecPart4Tests.TryParseStreamDataBlockedFrame_ParsesAndFormatsTheFrameFields`.
- Updated `QuicFrameCodecPart4Tests.TryParseStreamsBlockedFrame_ParsesAndFormatsBidirectionalAndUnidirectionalVariants`.
- Updated `QuicFrameCodecPart4Tests.TryParseStreamsBlockedFrame_AcceptsValueAtTheEncodingLimit`.
- Updated `QuicFrameCodecPart4Tests.TryParseStreamsBlockedFrame_RejectsValuesAboveTheEncodingLimit`.
- Updated `QuicFrameCodecPart4FuzzTests.Fuzz_FrameCodecPart4_RoundTripsRepresentativeFrameShapesAndRejectsTruncation`.
- Updated `QuicFrameCodecTests.TryParseResetStreamFrame_ParsesAndFormatsAllFields`.
- Updated `QuicStreamFrameTests.TryParseStreamFrame_ParsesOffsetsLengthsAndPayloadBytes`.
- Updated `QuicStreamFrameTests.TryParseStreamFrame_UsesTheRemainderWhenLengthIsAbsent`.
- Updated `QuicStreamFrameTests.TryParseStreamFrame_AcceptsOffsetsAtTheStreamCeilingWhenLengthIsPresent`.
- Updated `QuicStreamFrameTests.TryParseStreamFrame_AcceptsOffsetsAtTheStreamCeilingWhenLengthIsAbsent`.
- Updated `QuicStreamFrameTests.TryParseStreamFrame_RoundTripsRepresentableStreamShapes`.
- Updated `QuicStreamFuzzTests.Fuzz_StreamParsing_RoundTripsRepresentativeFramesAndRejectsTruncation`.
- Updated `QuicFrameCodecFuzzTests.Fuzz_FrameCodec_RoundTripsRepresentativeFrameShapesAndRejectsTruncation`.
- Updated `QuicCryptoBufferTests.TryAddFrame_BuffersOutOfOrderFramesAndDequeuesContiguousBytes`.
- Updated `QuicCryptoBufferTests.TryAddFrame_AllowsConfiguredCapacityDuringHandshake`.
- Updated `QuicCryptoBufferTests.TryAddFrame_ClosesWithBufferExceededWhenCapacityIsNotExpanded`.
- Updated `QuicCryptoBufferTests.TryAddFrame_CanDiscardOverflowFramesAfterHandshakeCompletion`.
- Updated `QuicCryptoBufferTests.TryAddFrame_CanCloseAfterHandshakeCompletionInsteadOfDiscarding`.
- Added `QuicTransportParametersBenchmarks.ParseTransportParameters` and `QuicTransportParametersBenchmarks.FormatTransportParameters`.

## Tests Run and Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-restore`
- Result: `298 passed, 0 failed, 0 skipped`
- `dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicTransportParametersBenchmarks*"`
- Result: `2 benchmarks executed successfully` (`ParseTransportParameters`, `FormatTransportParameters`)

## Remaining Open Requirements In Scope
- `REQ-QUIC-RFC9000-S4-0001` through `REQ-QUIC-RFC9000-S4-0003`
- `REQ-QUIC-RFC9000-S4P1-0001` through `REQ-QUIC-RFC9000-S4P1-0004`
- `REQ-QUIC-RFC9000-S4P1-0010` through `REQ-QUIC-RFC9000-S4P1-0013`
- `REQ-QUIC-RFC9000-S4P1-0015`
- `REQ-QUIC-RFC9000-S4P2-0001` through `REQ-QUIC-RFC9000-S4P2-0005`
- `REQ-QUIC-RFC9000-S4P4-0001` through `REQ-QUIC-RFC9000-S4P4-0004`
- `REQ-QUIC-RFC9000-S4P5-0001`
- `REQ-QUIC-RFC9000-S4P5-0004` through `REQ-QUIC-RFC9000-S4P5-0008`
- `REQ-QUIC-RFC9000-S4P6-0001` through `REQ-QUIC-RFC9000-S4P6-0002`
- `REQ-QUIC-RFC9000-S4P6-0008` through `REQ-QUIC-RFC9000-S4P6-0011`
- `REQ-QUIC-RFC9000-S4P6-0013`

## Risks or Follow-up Notes
- The remaining blocked items need a connection-scoped flow-control and stream-state engine. Without that substrate, the repo can validate and round-trip flow-control wire shapes, but it cannot yet enforce advertised credit, track final sizes, or emit the required transport errors.
- `REQ-QUIC-RFC9000-S4P6-0006` is now rejected in the transport-parameter codec for oversized `initial_max_streams_*` values; the broader stream accounting slice still remains open.
- The benchmark runner emitted the expected low-iteration Dry-run warnings; the suite itself completed successfully.

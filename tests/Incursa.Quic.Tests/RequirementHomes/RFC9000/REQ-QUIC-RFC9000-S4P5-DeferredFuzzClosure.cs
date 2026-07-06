// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S4P5_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StreamFinFinalSizeFuzz_UsesOffsetPlusLengthAsTheFinalSize()
    {
        for (int iteration = 0; iteration < 32; iteration++)
        {
            ulong streamId = (ulong)(1 + (iteration % 4) * 4);
            ulong offset = (ulong)(iteration % 9);
            int length = iteration % 6;
            ulong expectedFinalSize = offset + (ulong)length;

            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 128,
                peerBidirectionalReceiveLimit: 128);

            QuicStreamFrame frame = ParseStreamFrame(
                streamId,
                BuildFinStreamFrame(streamId, BuildPayload(length, iteration), offset));

            Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
            Assert.True(snapshot.HasFinalSize);
            Assert.Equal(expectedFinalSize, snapshot.FinalSize);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ResetStreamFinalSizeFuzz_RoundTripsTheFinalSizeField()
    {
        ulong[] finalSizes =
        [
            0UL,
            1UL,
            63UL,
            64UL,
            16_383UL,
            16_384UL,
            QuicVariableLengthInteger.MaxValue,
        ];

        foreach (ulong finalSize in finalSizes)
        {
            QuicResetStreamFrame frame = new(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize);
            byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

            Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.Equal(frame.StreamId, parsed.StreamId);
            Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
            Assert.Equal(finalSize, parsed.FinalSize);

            byte[] destination = new byte[32];
            Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FinalSizeChangeFuzz_RejectsStreamAndResetSignalsThatChangeKnownFinalSize()
    {
        for (ulong finalSize = 0; finalSize < 16; finalSize++)
        {
            QuicConnectionStreamState streamFinState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 64,
                peerBidirectionalReceiveLimit: 64);

            Assert.True(streamFinState.TryReceiveStreamFrame(
                ParseStreamFrame(1, BuildFinStreamFrame(1, BuildPayload((int)finalSize, seed: (int)finalSize), offset: 0)),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.False(streamFinState.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: finalSize + 1UL),
                out QuicMaxDataFrame maxDataFrame,
                out errorCode));
            Assert.Equal(default, maxDataFrame);
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

            QuicConnectionStreamState resetState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 64,
                peerBidirectionalReceiveLimit: 64);

            Assert.True(resetState.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize),
                out maxDataFrame,
                out errorCode));
            Assert.Equal(default, errorCode);

            Assert.False(resetState.TryReceiveStreamFrame(
                ParseStreamFrame(1, BuildFinStreamFrame(1, [0xAA], offset: finalSize)),
                out errorCode));
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
        }
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] frameBytes)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(frameBytes, out QuicStreamFrame frame));
        Assert.Equal(streamId, frame.StreamId.Value);
        return frame;
    }

    private static byte[] BuildFinStreamFrame(ulong streamId, byte[] payload, ulong offset)
    {
        if (payload.Length == 0)
        {
            return QuicStreamTestData.BuildStreamFrame(
                offset == 0 ? (byte)0x09 : (byte)0x0D,
                streamId,
                payload,
                offset: offset);
        }

        return QuicStreamTestData.BuildStreamFrame(0x0F, streamId, payload, offset: offset);
    }

    private static byte[] BuildPayload(int length, int seed)
    {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)(seed + index + 1);
        }

        return payload;
    }
}

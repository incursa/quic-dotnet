// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P10_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MaxStreamDataFrameWireFuzz_RoundTripsTypeStreamIdAndCreditFields()
    {
        Random random = new(0x5191_000A);
        Span<byte> destination = stackalloc byte[32];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            ulong streamId = SelectVarintBoundaryOrRandom(random, iteration);
            ulong maximumStreamData = SelectVarintBoundaryOrRandom(random, iteration + 3);
            QuicMaxStreamDataFrame frame = new(streamId, maximumStreamData);
            byte[] encoded = QuicFrameTestData.BuildMaxStreamDataFrame(frame);

            Assert.Equal(QuicS19P10MaxStreamDataFrameTestSupport.MaxStreamDataFrameType, encoded[0]);
            Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(encoded, out QuicMaxStreamDataFrame parsed, out int bytesConsumed));
            Assert.Equal(streamId, parsed.StreamId);
            Assert.Equal(maximumStreamData, parsed.MaximumStreamData);
            Assert.Equal(encoded.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatMaxStreamDataFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));

            if (encoded.Length > 1)
            {
                Assert.False(QuicFrameCodec.TryParseMaxStreamDataFrame(encoded[..^1], out _, out _));
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MaxStreamDataCreditFuzz_AdvertisesRecvStateAndAppliesAffectedStreamCredit()
    {
        Random random = new(0x5191_000B);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int readLength = random.Next(1, 8);
            ulong advertisedReceiveLimit = 64UL + (ulong)iteration;
            QuicConnectionStreamState receiveState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 512,
                localBidirectionalReceiveLimit: advertisedReceiveLimit);

            Assert.True(receiveState.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId receiveStreamId,
                out QuicStreamsBlockedFrame receiveBlockedFrame));
            Assert.Equal(default, receiveBlockedFrame);
            Assert.True(receiveState.TryGetStreamSnapshot(receiveStreamId.Value, out QuicConnectionStreamSnapshot initialReceiveSnapshot));
            Assert.Equal(QuicStreamReceiveState.Recv, initialReceiveSnapshot.ReceiveState);

            byte[] inboundData = RandomBytes(random, readLength);
            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x0E, receiveStreamId.Value, inboundData, offset: 0),
                out QuicStreamFrame inboundFrame));
            Assert.True(receiveState.TryReceiveStreamFrame(inboundFrame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            byte[] destination = new byte[readLength];
            Assert.True(receiveState.TryReadStreamData(
                receiveStreamId.Value,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out QuicMaxStreamDataFrame advertisedCredit,
                out errorCode));

            Assert.Equal(default, errorCode);
            Assert.Equal(readLength, bytesWritten);
            Assert.False(completed);
            Assert.True(inboundData.AsSpan().SequenceEqual(destination));
            Assert.Equal(receiveStreamId.Value, advertisedCredit.StreamId);
            Assert.Equal(advertisedReceiveLimit + (ulong)readLength, advertisedCredit.MaximumStreamData);

            QuicConnectionStreamState sendState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 512,
                connectionSendLimit: 512,
                localBidirectionalSendLimit: 16);
            Assert.True(sendState.TryOpenLocalStream(true, out QuicStreamId firstSendStreamId, out QuicStreamsBlockedFrame firstBlockedFrame));
            Assert.Equal(default, firstBlockedFrame);
            Assert.True(sendState.TryOpenLocalStream(true, out QuicStreamId secondSendStreamId, out QuicStreamsBlockedFrame secondBlockedFrame));
            Assert.Equal(default, secondBlockedFrame);

            ulong increasedLimit = 32UL + (ulong)iteration;
            Assert.True(sendState.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(secondSendStreamId.Value, increasedLimit), out errorCode));
            Assert.Equal(default, errorCode);
            Assert.False(sendState.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(secondSendStreamId.Value, increasedLimit - 1), out errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(sendState.TryGetStreamSnapshot(firstSendStreamId.Value, out QuicConnectionStreamSnapshot firstSendSnapshot));
            Assert.True(sendState.TryGetStreamSnapshot(secondSendStreamId.Value, out QuicConnectionStreamSnapshot secondSendSnapshot));
            Assert.Equal(16UL, firstSendSnapshot.SendLimit);
            Assert.Equal(increasedLimit, secondSendSnapshot.SendLimit);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void SparseReceiveOffsetFuzz_AllowsLargestOffsetToExceedUniqueBytes()
    {
        Random random = new(0x5191_000C);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            ulong offset = (ulong)random.Next(1, 96);
            int length = random.Next(1, 8);
            byte[] tailData = RandomBytes(random, length);
            ulong largestOffset = offset + (ulong)length;
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 512,
                peerBidirectionalReceiveLimit: 512);

            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x0E, 1, tailData, offset),
                out QuicStreamFrame tailFrame));
            Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot sparseSnapshot));
            Assert.Equal((ulong)length, sparseSnapshot.UniqueBytesReceived);
            Assert.True(largestOffset > sparseSnapshot.UniqueBytesReceived);
            Assert.Equal(length, sparseSnapshot.BufferedReadableBytes);
            Assert.Equal(0UL, sparseSnapshot.ReadOffset);

            Assert.False(state.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: largestOffset - 1),
                out _,
                out errorCode));
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
        }
    }

    private static ulong SelectVarintBoundaryOrRandom(Random random, int iteration)
        => (iteration % 8) switch
        {
            0 => 0UL,
            1 => 63UL,
            2 => 64UL,
            3 => 16_383UL,
            4 => 16_384UL,
            5 => 1_073_741_823UL,
            6 => 1_073_741_824UL,
            _ => (ulong)random.Next(0, 1 << 20),
        };

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}

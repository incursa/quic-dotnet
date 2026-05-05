namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0001")]
public sealed class REQ_QUIC_RFC9000_S19P10_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_EmitsMaxStreamDataFrameToAdvertiseRecvStateCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot initialSnapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, initialSnapshot.ReceiveState);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId.Value, [0x11, 0x22], offset: 0),
            out QuicStreamFrame inboundFrame));

        Assert.True(state.TryReceiveStreamFrame(inboundFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            streamId.Value,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.True(destination.SequenceEqual(new byte[] { 0x11, 0x22 }));
        Assert.Equal(18UL, maxDataFrame.MaximumData);
        Assert.Equal(streamId.Value, maxStreamDataFrame.StreamId);
        Assert.Equal(10UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(10UL, snapshot.ReceiveLimit);
        Assert.Equal(2UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_DoesNotEmitMaxStreamDataFrameWhenNoCreditIsReleased()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Span<byte> destination = stackalloc byte[1];
        Assert.False(state.TryReadStreamData(
            streamId.Value,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_AdvertisesCumulativeAbsoluteStreamCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame inboundFrame));
        Assert.True(state.TryReceiveStreamFrame(inboundFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> firstDestination = stackalloc byte[1];
        Assert.True(state.TryReadStreamData(
            1,
            firstDestination,
            out int firstBytesWritten,
            out bool firstCompleted,
            out _,
            out QuicMaxStreamDataFrame firstMaxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(1, firstBytesWritten);
        Assert.False(firstCompleted);
        Assert.Equal(1UL, firstMaxStreamDataFrame.StreamId);
        Assert.Equal(9UL, firstMaxStreamDataFrame.MaximumStreamData);

        Span<byte> secondDestination = stackalloc byte[1];
        Assert.True(state.TryReadStreamData(
            1,
            secondDestination,
            out int secondBytesWritten,
            out bool secondCompleted,
            out _,
            out QuicMaxStreamDataFrame secondMaxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(1, secondBytesWritten);
        Assert.False(secondCompleted);
        Assert.Equal(1UL, secondMaxStreamDataFrame.StreamId);
        Assert.Equal(10UL, secondMaxStreamDataFrame.MaximumStreamData);
    }
}

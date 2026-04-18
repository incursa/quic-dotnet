namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0011")]
public sealed class REQ_QUIC_RFC9000_S19P10_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_AllowsTheLargestReceivedOffsetToExceedTheUniqueBytesReceived()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x33, 0x44], offset: 4),
            out QuicStreamFrame tailFrame));
        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame headFrame));
        Assert.True(state.TryReceiveStreamFrame(headFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(4UL, snapshot.UniqueBytesReceived);
        Assert.Equal(4UL, snapshot.AccountedBytesReceived);
        Assert.Equal(4, snapshot.BufferedReadableBytes);
        Assert.Equal(0UL, snapshot.ReadOffset);

        Assert.False(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out _,
            out errorCode));

        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
    }
}

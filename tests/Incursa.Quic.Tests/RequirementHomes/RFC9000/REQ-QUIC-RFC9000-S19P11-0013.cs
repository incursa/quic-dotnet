namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P11-0013")]
public sealed class REQ_QUIC_RFC9000_S19P11_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_CountsClosedStreamsAgainstTheAdvertisedCumulativeLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingUnidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 3, streamData: []),
            out QuicStreamFrame firstClosedStreamFrame));
        Assert.True(state.TryReceiveStreamFrame(firstClosedStreamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryPeekPeerStreamCapacityRelease(3, out QuicMaxStreamsFrame releaseFrame));
        Assert.False(releaseFrame.IsBidirectional);
        Assert.Equal(2UL, releaseFrame.MaximumStreams);
        Assert.True(state.TryCommitPeerStreamCapacityRelease(3, releaseFrame));

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 7, streamData: []),
            out QuicStreamFrame secondClosedStreamFrame));
        Assert.True(state.TryReceiveStreamFrame(secondClosedStreamFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, streamId: 11, streamData: [0x51]),
            out QuicStreamFrame thirdStreamFrame));
        Assert.False(state.TryReceiveStreamFrame(thirdStreamFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }
}

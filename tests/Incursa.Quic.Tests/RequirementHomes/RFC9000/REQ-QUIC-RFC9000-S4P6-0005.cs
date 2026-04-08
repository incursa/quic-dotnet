namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
public sealed class REQ_QUIC_RFC9000_S4P6_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_UsesSeparateBidirectionalAndUnidirectionalLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 1,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId bidiFirstStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryOpenLocalStream(bidirectional: true, out _, out blockedFrame));
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId uniFirstStreamId, out blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId uniSecondStreamId, out blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryOpenLocalStream(bidirectional: false, out _, out blockedFrame));
        Assert.False(blockedFrame.IsBidirectional);
        Assert.Equal(2UL, blockedFrame.MaximumStreams);
    }
}

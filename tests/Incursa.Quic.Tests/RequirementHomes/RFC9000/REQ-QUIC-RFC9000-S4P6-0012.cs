namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0012")]
public sealed class REQ_QUIC_RFC9000_S4P6_0012
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_ReturnsStreamsBlockedWhenThePeerLimitIsReached()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(peerBidirectionalStreamLimit: 1);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out _, out _));

        Assert.False(state.TryOpenLocalStream(bidirectional: true, out _, out QuicStreamsBlockedFrame blockedFrame));
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);
    }
}

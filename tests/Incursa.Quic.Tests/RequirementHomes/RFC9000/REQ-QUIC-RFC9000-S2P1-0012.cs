namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S2P1-0012")]
public sealed class REQ_QUIC_RFC9000_S2P1_0012
{
    [Theory]
    [InlineData(false, true, 0UL)]
    [InlineData(false, false, 2UL)]
    [InlineData(true, true, 1UL)]
    [InlineData(true, false, 3UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_StartsEachStreamSpaceAtItsMinimumValue(
        bool isServer,
        bool bidirectional,
        ulong expectedStreamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(isServer: isServer);

        Assert.True(state.TryPeekLocalStream(bidirectional, out QuicStreamId peekedStreamId, out QuicStreamsBlockedFrame peekBlockedFrame));
        Assert.Equal(expectedStreamId, peekedStreamId.Value);
        Assert.Equal(default, peekBlockedFrame);

        Assert.True(state.TryOpenLocalStream(bidirectional, out QuicStreamId openedStreamId, out QuicStreamsBlockedFrame openedBlockedFrame));
        Assert.Equal(expectedStreamId, openedStreamId.Value);
        Assert.Equal(default, openedBlockedFrame);
    }
}

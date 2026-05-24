namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0045")]
public sealed class REQ_QUIC_RFC9000_0045
{
    [Theory]
    [InlineData(false, true, 0UL, 4UL)]
    [InlineData(false, false, 2UL, 6UL)]
    [InlineData(true, true, 1UL, 5UL)]
    [InlineData(true, false, 3UL, 7UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_IncreasesStreamIdsForEachStreamType(
        bool isServer,
        bool bidirectional,
        ulong firstExpectedStreamId,
        ulong secondExpectedStreamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(isServer: isServer);

        Assert.True(state.TryOpenLocalStream(bidirectional, out QuicStreamId firstStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(firstExpectedStreamId, firstStreamId.Value);
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryOpenLocalStream(bidirectional, out QuicStreamId secondStreamId, out blockedFrame));
        Assert.Equal(secondExpectedStreamId, secondStreamId.Value);
        Assert.Equal(default, blockedFrame);
        Assert.True(secondStreamId.Value > firstStreamId.Value);
    }

    [Theory]
    [InlineData(false, true, 0UL, 4UL)]
    [InlineData(false, false, 2UL, 6UL)]
    [InlineData(true, true, 1UL, 5UL)]
    [InlineData(true, false, 3UL, 7UL)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_DoesNotSkipTheNextIncreasingIdAfterABlockedAttempt(
        bool isServer,
        bool bidirectional,
        ulong firstExpectedStreamId,
        ulong secondExpectedStreamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: isServer,
            peerBidirectionalStreamLimit: bidirectional ? 1UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 1UL);

        Assert.True(state.TryOpenLocalStream(bidirectional, out QuicStreamId firstStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(firstExpectedStreamId, firstStreamId.Value);

        Assert.False(state.TryOpenLocalStream(bidirectional, out QuicStreamId blockedStreamId, out blockedFrame));
        Assert.Equal(default, blockedStreamId);
        Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(bidirectional, 2)));

        Assert.True(state.TryOpenLocalStream(bidirectional, out QuicStreamId secondStreamId, out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(secondExpectedStreamId, secondStreamId.Value);
        Assert.True(secondStreamId.Value > firstStreamId.Value);
    }
}

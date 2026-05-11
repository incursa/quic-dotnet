namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0010">Once a receiver advertises a stream limit using the MAX_STREAMS frame, advertising a smaller limit MUST have no effect.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P6-0010")]
public sealed class REQ_QUIC_RFC9000_S4P6_0010
{
    [Theory]
    [InlineData(true, 0UL, 4UL)]
    [InlineData(false, 2UL, 6UL)]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamsFrame_IncreasesTheAdvertisedStreamLimit(
        bool bidirectional,
        ulong firstExpectedStreamId,
        ulong secondExpectedStreamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? 1UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 1UL);

        Assert.True(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId firstStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(firstExpectedStreamId, firstStreamId.Value);

        Assert.False(state.TryOpenLocalStream(bidirectional, out _, out blockedFrame));
        Assert.Equal(1UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(bidirectional, 2)));

        Assert.True(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId secondStreamId,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(secondExpectedStreamId, secondStreamId.Value);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamsFrame_IgnoresSmallerBidirectionalLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);

        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 2)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxStreamsFrame_IgnoresStaleLimitAfterMultipleIncreases(bool bidirectional)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? 1UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 1UL);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(bidirectional, 2)));
        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(bidirectional, 4)));

        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(bidirectional, 3)));

        Assert.Equal(4UL, state.PeerBidirectionalStreamLimit);
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);
    }
}

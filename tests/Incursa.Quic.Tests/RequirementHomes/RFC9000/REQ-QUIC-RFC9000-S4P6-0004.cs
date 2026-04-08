namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0004")]
public sealed class REQ_QUIC_RFC9000_S4P6_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamsFrame_AdvertisesLaterLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 3);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 4)));
        Assert.Equal(4UL, state.PeerBidirectionalStreamLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 5)));
        Assert.Equal(5UL, state.PeerUnidirectionalStreamLimit);
    }
}

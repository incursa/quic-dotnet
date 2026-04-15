namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P1-0011")]
public sealed class REQ_QUIC_RFC9000_S4P1_0011
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxFrames_AdvertisesLargerAdvertisedLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalSendLimit: 4,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.Equal(12UL, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot streamSnapshot));
        Assert.Equal(10UL, streamSnapshot.SendLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxFrames_IgnoresSmallerAdvertisedLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalSendLimit: 4,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(11)));
        Assert.Equal(12UL, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 9), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 2)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 3)));
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0011")]
public sealed class REQ_QUIC_RFC9000_S18P2_0011
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0011")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenLocalStream_BlocksBidirectionalStreamsUntilPeerMaxStreamsIncreases()
    {
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            [],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));
        Assert.Null(parsedTransportParameters.InitialMaxStreamsBidi);

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: parsedTransportParameters.InitialMaxStreamsBidi ?? 0);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(0UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 1)));
        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out blockedFrame));

        Assert.Equal(0UL, streamId.Value);
        Assert.Equal(default, blockedFrame);
    }
}

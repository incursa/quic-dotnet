namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0014")]
public sealed class REQ_QUIC_RFC9000_S18P2_0014
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0014")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenLocalStream_BlocksUnidirectionalStreamsUntilPeerMaxStreamsIncreases()
    {
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            [],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));
        Assert.Null(parsedTransportParameters.InitialMaxStreamsUni);

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerUnidirectionalStreamLimit: parsedTransportParameters.InitialMaxStreamsUni ?? 0);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: false,
            out _,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.False(blockedFrame.IsBidirectional);
        Assert.Equal(0UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 1)));
        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out blockedFrame));

        Assert.Equal(2UL, streamId.Value);
        Assert.Equal(default, blockedFrame);
    }
}

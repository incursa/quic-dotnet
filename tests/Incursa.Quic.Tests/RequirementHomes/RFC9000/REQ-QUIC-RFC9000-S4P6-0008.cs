namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0008")]
public sealed class REQ_QUIC_RFC9000_S4P6_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_DoesNotExceedThePeerBidirectionalStreamLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(peerBidirectionalStreamLimit: 1);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId firstStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);

        Assert.False(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId secondStreamId, out blockedFrame));
        Assert.Equal(default, secondStreamId);
    }
}

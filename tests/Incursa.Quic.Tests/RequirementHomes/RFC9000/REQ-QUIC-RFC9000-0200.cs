namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0200")]
public sealed class REQ_QUIC_RFC9000_0200
{
    [Theory]
    [InlineData(true, 0UL, 4UL)]
    [InlineData(false, 2UL, 6UL)]
    [Requirement("REQ-QUIC-RFC9000-0200")]
    [Requirement("REQ-QUIC-RFC9000-0031")]
    [Requirement("REQ-QUIC-RFC9000-0034")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_AllowsStreamsWithinThePeerStreamLimit(
        bool bidirectional,
        ulong firstExpectedStreamId,
        ulong secondExpectedStreamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? 2UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 2UL);

        Assert.True(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId firstStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(firstExpectedStreamId, firstStreamId.Value);

        Assert.True(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId secondStreamId,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(secondExpectedStreamId, secondStreamId.Value);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.True(state.TryGetStreamSnapshot(secondStreamId.Value, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(QuicStreamSendState.Ready, firstSnapshot.SendState);
        Assert.Equal(QuicStreamSendState.Ready, secondSnapshot.SendState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0200")]
    [Requirement("REQ-QUIC-RFC9000-0034")]
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

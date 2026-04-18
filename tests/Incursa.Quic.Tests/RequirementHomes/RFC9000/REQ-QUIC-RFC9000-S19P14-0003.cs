namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0003">A STREAMS_BLOCKED frame MUST NOT open the stream, but informs the peer that a new stream was needed and the stream limit prevented the creation of the stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P14-0003")]
public sealed class REQ_QUIC_RFC9000_S19P14_0003
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_DoesNotOpenAnotherLocalStreamWhenItReturnsStreamsBlocked(bool bidirectional)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? 1UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 1UL);

        Assert.True(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId firstStreamId,
            out QuicStreamsBlockedFrame firstBlockedFrame));
        Assert.Equal(default, firstBlockedFrame);
        Assert.Equal(bidirectional ? 0UL : 2UL, firstStreamId.Value);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot initialSnapshot));
        Assert.Equal(QuicStreamSendState.Ready, initialSnapshot.SendState);

        Assert.False(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId blockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedStreamId);
        Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot afterSnapshot));
        Assert.Equal(initialSnapshot, afterSnapshot);
        Assert.False(state.TryGetStreamSnapshot(firstStreamId.Value + 4UL, out _));
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0009">An endpoint MUST NOT open more streams than permitted by the current stream limit set by its peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P11-0009")]
public sealed class REQ_QUIC_RFC9000_S19P11_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_AllowsOpeningWithinThePeerLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 1,
            peerUnidirectionalStreamLimit: 1);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(0UL, streamId.Value);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_BlocksOpeningPastThePeerLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 1,
            peerUnidirectionalStreamLimit: 1);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out _));

        Assert.False(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId blockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedStreamId);
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);
    }
}

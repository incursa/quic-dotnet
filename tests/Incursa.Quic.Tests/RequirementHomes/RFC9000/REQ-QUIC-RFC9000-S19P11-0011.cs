namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0011">This MUST include violations of remembered limits in Early Data; see Section 7.4.1.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P11-0011")]
public sealed class REQ_QUIC_RFC9000_S19P11_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_ContinuesToHonorTheRememberedLimitAfterTheFirstStreamIsClosed()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 0,
            peerUnidirectionalStreamLimit: 1);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 0,
            fin: true,
            out _,
            out _,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryAcknowledgeSendCompletion(streamId.Value));

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.DataRecvd, snapshot.SendState);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId blockedStreamId,
            out QuicStreamsBlockedFrame blockedFrameAfterClosure));
        Assert.Equal(default, blockedStreamId);
        Assert.False(blockedFrameAfterClosure.IsBidirectional);
        Assert.Equal(1UL, blockedFrameAfterClosure.MaximumStreams);
    }
}

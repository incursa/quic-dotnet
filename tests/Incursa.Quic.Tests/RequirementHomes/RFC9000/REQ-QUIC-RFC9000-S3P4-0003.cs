namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P4-0003">Any mapping to a closed or half-closed state MUST require data to be acknowledged before the transition.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P4-0003")]
public sealed class REQ_QUIC_RFC9000_S3P4_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P4-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcknowledgeSendCompletion_EntersDataRecvdAfterAcknowledgeableBidirectionalData()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: true,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sentSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, sentSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, sentSnapshot.ReceiveState);

        Assert.True(state.TryAcknowledgeSendCompletion(streamId.Value));

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot acknowledgedSnapshot));
        Assert.Equal(QuicStreamSendState.DataRecvd, acknowledgedSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, acknowledgedSnapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P4-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcknowledgeSendCompletion_DoesNotAdvanceBidirectionalStreamWithoutFinalData()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);

        Assert.False(state.TryAcknowledgeSendCompletion(streamId.Value));

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot afterSnapshot));
        Assert.Equal(QuicStreamSendState.Send, afterSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, afterSnapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P4-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAcknowledgeSendCompletion_HandlesZeroLengthBidirectionalFin()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 0,
            fin: true,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sentSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, sentSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, sentSnapshot.ReceiveState);

        Assert.True(state.TryAcknowledgeSendCompletion(streamId.Value));

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot acknowledgedSnapshot));
        Assert.Equal(QuicStreamSendState.DataRecvd, acknowledgedSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, acknowledgedSnapshot.ReceiveState);
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0006">If the stream is in the Data Sent state, the endpoint MAY defer sending the RESET_STREAM frame until the packets containing outstanding data are acknowledged or declared lost.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0006")]
public sealed class REQ_QUIC_RFC9000_S3P5_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStopSendingFrame_AllowsDataSentAndProducesResetStreamFrame()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
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

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
        Assert.True(dataSentSnapshot.HasFinalSize);
        Assert.Equal(2UL, dataSentSnapshot.FinalSize);

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x77),
            out QuicResetStreamFrame resetStreamFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(streamId.Value, resetStreamFrame.StreamId);
        Assert.Equal(0x77UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(2UL, resetStreamFrame.FinalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.FinalSize);
        Assert.True(snapshot.HasSendAbortErrorCode);
        Assert.Equal(0x77UL, snapshot.SendAbortErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStopSendingFrame_RejectsAfterDataSentHasBeenAcknowledged()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
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

        Assert.True(state.TryAcknowledgeSendCompletion(streamId.Value));
        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot acknowledgedSnapshot));
        Assert.Equal(QuicStreamSendState.DataRecvd, acknowledgedSnapshot.SendState);
        Assert.True(acknowledgedSnapshot.HasFinalSize);
        Assert.Equal(2UL, acknowledgedSnapshot.FinalSize);

        Assert.False(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x77),
            out QuicResetStreamFrame resetStreamFrame,
            out errorCode));
        Assert.Equal(default, resetStreamFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.DataRecvd, snapshot.SendState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.FinalSize);
        Assert.False(snapshot.HasSendAbortErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStopSendingFrame_DataSentBidirectionalStreamTerminatesOnlyTheSendDirection()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 5,
            fin: true,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
        Assert.Equal(QuicStreamType.Bidirectional, dataSentSnapshot.StreamType);
        Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, dataSentSnapshot.ReceiveState);
        Assert.True(dataSentSnapshot.HasFinalSize);
        Assert.Equal(5UL, dataSentSnapshot.FinalSize);

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x88),
            out QuicResetStreamFrame resetStreamFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(streamId.Value, resetStreamFrame.StreamId);
        Assert.Equal(0x88UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(5UL, resetStreamFrame.FinalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(5UL, snapshot.FinalSize);
        Assert.True(snapshot.HasSendAbortErrorCode);
        Assert.Equal(0x88UL, snapshot.SendAbortErrorCode);
    }
}

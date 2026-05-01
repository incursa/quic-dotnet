namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P3-0005">A receiver MAY send a STOP_SENDING frame in any state where it has not received a RESET_STREAM frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P3-0005")]
public sealed class REQ_QUIC_RFC9000_S3P3_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P3-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStopSendingFrame_AllowsStopSendingInReadyState()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x55),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(streamId.Value, resetStreamFrame.StreamId);
        Assert.Equal(0x55UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, resetStreamFrame.FinalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot afterSnapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, afterSnapshot.SendState);
        Assert.True(afterSnapshot.HasFinalSize);
        Assert.Equal(0UL, afterSnapshot.FinalSize);
        Assert.True(afterSnapshot.HasSendAbortErrorCode);
        Assert.Equal(0x55UL, afterSnapshot.SendAbortErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P3-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStopSendingFrame_AllowsStopSendingBeforeResetReception()
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

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x66),
            out QuicResetStreamFrame resetStreamFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(streamId.Value, resetStreamFrame.StreamId);
        Assert.Equal(0x66UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(2UL, resetStreamFrame.FinalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.FinalSize);
        Assert.True(snapshot.HasSendAbortErrorCode);
        Assert.Equal(0x66UL, snapshot.SendAbortErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P3-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStopSendingFrame_RejectsStopSendingAfterResetReception()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId.Value, 0x99, 0),
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);

        Assert.False(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x44),
            out QuicResetStreamFrame resetStreamFrame,
            out errorCode));
        Assert.Equal(default, resetStreamFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P3-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStopSendingFrame_AllowsStopSendingAfterReceiveSideDataRead()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            localBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 8,
            localBidirectionalReceiveLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId.Value, [0x11], offset: 0),
            out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[1];
        Assert.True(state.TryReadStreamData(
            streamId.Value,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(1, bytesWritten);
        Assert.True(completed);
        Assert.Equal(0x11, destination[0]);
        Assert.NotEqual(default, maxDataFrame);
        Assert.NotEqual(default, maxStreamDataFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataReadSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, dataReadSnapshot.ReceiveState);
        Assert.Equal(QuicStreamSendState.Ready, dataReadSnapshot.SendState);

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x77),
            out QuicResetStreamFrame resetStreamFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(streamId.Value, resetStreamFrame.StreamId);
        Assert.Equal(0x77UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, resetStreamFrame.FinalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot resetSentSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, resetSentSnapshot.ReceiveState);
        Assert.Equal(QuicStreamSendState.ResetSent, resetSentSnapshot.SendState);
    }
}

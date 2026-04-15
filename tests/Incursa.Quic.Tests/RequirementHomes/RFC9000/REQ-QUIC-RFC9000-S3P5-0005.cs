namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0005">An endpoint that receives a STOP_SENDING frame MUST send a RESET_STREAM frame if the stream is in the Ready or Send state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0005")]
public sealed class REQ_QUIC_RFC9000_S3P5_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStopSendingFrame_SendsResetStreamFromReadyAndSendStates()
    {
        QuicConnectionStreamState readyState = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(readyState.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId readyStreamId,
            out QuicStreamsBlockedFrame readyBlockedFrame));
        Assert.Equal(default, readyBlockedFrame);

        Assert.True(readyState.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(readyStreamId.Value, 0x99),
            out QuicResetStreamFrame readyResetStreamFrame,
            out QuicTransportErrorCode readyErrorCode));
        Assert.Equal(default, readyErrorCode);
        Assert.Equal(readyStreamId.Value, readyResetStreamFrame.StreamId);
        Assert.Equal(0x99UL, readyResetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, readyResetStreamFrame.FinalSize);

        Assert.True(readyState.TryGetStreamSnapshot(readyStreamId.Value, out QuicConnectionStreamSnapshot readySnapshot));
        Assert.Equal(QuicStreamType.Unidirectional, readySnapshot.StreamType);
        Assert.Equal(QuicStreamSendState.ResetSent, readySnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.None, readySnapshot.ReceiveState);
        Assert.True(readySnapshot.HasFinalSize);
        Assert.Equal(0UL, readySnapshot.FinalSize);
        Assert.True(readySnapshot.HasSendAbortErrorCode);
        Assert.Equal(0x99UL, readySnapshot.SendAbortErrorCode);

        QuicConnectionStreamState sendState = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(sendState.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId sendStreamId,
            out QuicStreamsBlockedFrame sendBlockedFrame));
        Assert.Equal(default, sendBlockedFrame);

        Assert.True(sendState.TryReserveSendCapacity(
            sendStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode sendErrorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, sendErrorCode);

        Assert.True(sendState.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(sendStreamId.Value, 0x66),
            out QuicResetStreamFrame sendResetStreamFrame,
            out sendErrorCode));
        Assert.Equal(default, sendErrorCode);
        Assert.Equal(sendStreamId.Value, sendResetStreamFrame.StreamId);
        Assert.Equal(0x66UL, sendResetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(2UL, sendResetStreamFrame.FinalSize);

        Assert.True(sendState.TryGetStreamSnapshot(sendStreamId.Value, out QuicConnectionStreamSnapshot sendSnapshot));
        Assert.Equal(QuicStreamType.Unidirectional, sendSnapshot.StreamType);
        Assert.Equal(QuicStreamSendState.ResetSent, sendSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.None, sendSnapshot.ReceiveState);
        Assert.True(sendSnapshot.HasFinalSize);
        Assert.Equal(2UL, sendSnapshot.FinalSize);
        Assert.True(sendSnapshot.HasSendAbortErrorCode);
        Assert.Equal(0x66UL, sendSnapshot.SendAbortErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStopSendingFrame_RejectsPeerInitiatedUnidirectionalStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.False(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(3, 0x99),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, resetStreamFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }
}

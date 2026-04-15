namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0014">From any state that is Ready, Send, or Data Sent, an application MAY signal that it wishes to abandon transmission of stream data.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P1-0014")]
public sealed class REQ_QUIC_RFC9000_S3P1_0014
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAbortLocalStreamWrites_AllowsApplicationAbandonmentFromReadySendAndDataSentStates()
    {
        QuicConnectionStreamState readyState = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(readyState.TryAbortLocalStreamWrites(0, out ulong readyFinalSize, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0UL, readyFinalSize);
        Assert.True(readyState.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot readySnapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, readySnapshot.SendState);

        QuicConnectionStreamState sendState = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);
        Assert.True(sendState.TryOpenLocalStream(false, out QuicStreamId sendStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.True(sendState.TryReserveSendCapacity(
            sendStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(sendState.TryAbortLocalStreamWrites(sendStreamId.Value, out ulong sendFinalSize, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, sendFinalSize);
        Assert.True(sendState.TryGetStreamSnapshot(sendStreamId.Value, out QuicConnectionStreamSnapshot sendSnapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, sendSnapshot.SendState);

        QuicConnectionStreamState dataSentState = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);
        Assert.True(dataSentState.TryOpenLocalStream(false, out QuicStreamId dataSentStreamId, out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.True(dataSentState.TryReserveSendCapacity(
            dataSentStreamId.Value,
            offset: 0,
            length: 2,
            fin: true,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(dataSentState.TryAbortLocalStreamWrites(dataSentStreamId.Value, out ulong dataSentFinalSize, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, dataSentFinalSize);
        Assert.True(dataSentState.TryGetStreamSnapshot(dataSentStreamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, dataSentSnapshot.SendState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAbortLocalStreamWrites_RejectsPeerInitiatedStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.False(state.TryAbortLocalStreamWrites(1, out ulong finalSize, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, finalSize);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }
}

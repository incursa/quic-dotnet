namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0015">In either case, the endpoint MUST send a RESET_STREAM frame, which causes the stream to enter the Reset Sent state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P1-0015")]
public sealed class REQ_QUIC_RFC9000_S3P1_0015
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0015")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAbortLocalStreamWrites_EntersResetSentAfterAbandoningTransmission()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 3,
            fin: false,
            out _,
            out _,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryAbortLocalStreamWrites(streamId.Value, out ulong finalSize, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(3UL, finalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(3UL, snapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAbortLocalStreamWrites_RejectsRedundantAbandonmentAfterResetSent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 3,
            fin: false,
            out _,
            out _,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryAbortLocalStreamWrites(streamId.Value, out _, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryAbortLocalStreamWrites(streamId.Value, out ulong redundantFinalSize, out errorCode));
        Assert.Equal(default, redundantFinalSize);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.Equal(3UL, snapshot.FinalSize);
    }
}

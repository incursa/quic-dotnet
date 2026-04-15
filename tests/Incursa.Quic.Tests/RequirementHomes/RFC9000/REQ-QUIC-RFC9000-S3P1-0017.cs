namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0017">Once a packet containing a RESET_STREAM has been acknowledged, the sending part of the stream MUST enter the Reset Recvd state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P1-0017")]
public sealed class REQ_QUIC_RFC9000_S3P1_0017
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcknowledgeSendCompletion_EntersResetRecvdAfterResetStreamIsAcknowledged()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 8);

        Assert.True(state.TryAbortLocalStreamWrites(0, out ulong finalSize, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0UL, finalSize);

        Assert.True(state.TryAcknowledgeSendCompletion(0));

        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.ResetRecvd, snapshot.SendState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcknowledgeSendCompletion_RejectsRedundantAcksAfterResetIsRecvd()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 8);

        Assert.True(state.TryAbortLocalStreamWrites(0, out _, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryAcknowledgeSendCompletion(0));
        Assert.False(state.TryAcknowledgeSendCompletion(0));
    }
}

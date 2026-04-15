namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0009">Receiving a STOP_SENDING frame for an unopened stream MUST indicate that the remote peer no longer wishes to receive data on this stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0009")]
public sealed class REQ_QUIC_RFC9000_S3P2_0009
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStopSendingFrame_OpensUnopenedPeerBidirectionalStreamAndRecordsPeerAbortIntent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 128,
            connectionSendLimit: 128,
            incomingBidirectionalStreamLimit: 1024,
            incomingUnidirectionalStreamLimit: 1024,
            peerBidirectionalStreamLimit: 1024,
            peerUnidirectionalStreamLimit: 1024,
            peerBidirectionalReceiveLimit: 32,
            peerUnidirectionalReceiveLimit: 32,
            localBidirectionalReceiveLimit: 32,
            localUnidirectionalSendLimit: 32,
            peerBidirectionalSendLimit: 8);

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(1, 0x99),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, resetStreamFrame.StreamId);
        Assert.Equal(0x99UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, resetStreamFrame.FinalSize);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(0UL, snapshot.FinalSize);
        Assert.True(snapshot.HasSendAbortErrorCode);
        Assert.Equal(0x99UL, snapshot.SendAbortErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStopSendingFrame_RejectsLocallyInitiatedUnopenedStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.False(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(0, 0x99),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, resetStreamFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(0, out _));
    }
}

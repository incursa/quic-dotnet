namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P2-0021")]
public sealed class REQ_QUIC_RFC9000_S3P2_0021
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0021">Receiving a RESET_STREAM frame in the Recv or Size Known state MUST cause the stream to enter the Reset Recvd state.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveResetStreamFrame_EntersResetRecvdWhenResetStreamArrives()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x21, 0x22], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(18UL, maxDataFrame.MaximumData);
        Assert.Equal(5UL, state.ConnectionAccountedBytesReceived);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(5UL, snapshot.FinalSize);
        Assert.Equal(0, snapshot.BufferedReadableBytes);

        Assert.False(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 6),
            out _,
            out errorCode));
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P2-0022")]
public sealed class REQ_QUIC_RFC9000_S3P2_0022
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0022">An implementation MAY interrupt delivery of stream data, discard any data that was not consumed, and signal the receipt of the RESET_STREAM.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveResetStreamFrame_InterruptsPendingDeliveryAndDiscardsUnreadBytes()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, streamId: 1, streamData: [0x21, 0x22], offset: 0),
            out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot preResetSnapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, preResetSnapshot.ReceiveState);
        Assert.Equal(2, preResetSnapshot.BufferedReadableBytes);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(18UL, maxDataFrame.MaximumData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(5UL, snapshot.FinalSize);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
        Assert.True(snapshot.HasReceiveAbortErrorCode);
        Assert.Equal(0x99UL, snapshot.ReceiveAbortErrorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.False(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.False(completed);
    }
}

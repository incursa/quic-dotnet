namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P2-0023")]
public sealed class REQ_QUIC_RFC9000_S3P2_0023
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0023">If the RESET_STREAM is suppressed, the receiving part of the stream MUST remain in Data Recvd.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveResetStreamFrame_PreservesBufferedDataWhenTheResetSignalIsSuppressed()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, streamData: [0x11, 0x22, 0x33, 0x44], offset: 0),
            out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot preResetSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, preResetSnapshot.ReceiveState);
        Assert.Equal(4, preResetSnapshot.BufferedReadableBytes);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 4),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode,
            suppressResetSignalWhenDataRecvd: true));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(4, snapshot.BufferedReadableBytes);
        Assert.False(snapshot.HasReceiveAbortErrorCode);

        Span<byte> destination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame postReadMaxDataFrame,
            out QuicMaxStreamDataFrame postReadMaxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.True(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(destination));
        Assert.NotEqual(default(QuicMaxDataFrame), postReadMaxDataFrame);
        Assert.NotEqual(default(QuicMaxStreamDataFrame), postReadMaxStreamDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }
}

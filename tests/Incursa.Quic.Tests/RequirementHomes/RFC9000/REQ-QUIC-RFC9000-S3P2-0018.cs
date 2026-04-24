namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0018">After all data has been received, any STREAM or STREAM_DATA_BLOCKED frames for the stream MAY be discarded.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0018")]
public sealed class REQ_QUIC_RFC9000_S3P2_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_DiscardsRedundantFramesAfterDataRecvd()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, [0x11, 0x22, 0x33, 0x44], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot preDiscardSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, preDiscardSnapshot.ReceiveState);
        Assert.True(preDiscardSnapshot.HasFinalSize);
        Assert.Equal(4UL, preDiscardSnapshot.FinalSize);
        Assert.Equal(4, preDiscardSnapshot.BufferedReadableBytes);

        Assert.True(state.TryReceiveStreamFrame(frame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamDataBlockedFrame(
            new QuicStreamDataBlockedFrame(streamId: 5, maximumStreamData: 4),
            out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot postDiscardSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, postDiscardSnapshot.ReceiveState);
        Assert.True(postDiscardSnapshot.HasFinalSize);
        Assert.Equal(4UL, postDiscardSnapshot.FinalSize);
        Assert.Equal(4, postDiscardSnapshot.BufferedReadableBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_RejectsBytesBeyondTheFinalSizeAfterDataRecvd()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, [0x11, 0x22, 0x33, 0x44], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] excessPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 5, [0x55], offset: 4);
        Assert.True(QuicStreamParser.TryParseStreamFrame(excessPacket, out QuicStreamFrame excessFrame));

        Assert.False(state.TryReceiveStreamFrame(excessFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(4, snapshot.BufferedReadableBytes);
    }
}

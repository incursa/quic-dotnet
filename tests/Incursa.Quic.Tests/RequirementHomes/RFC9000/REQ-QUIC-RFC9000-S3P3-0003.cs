namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P3-0003">A receiver MAY receive STREAM, STREAM_DATA_BLOCKED, or RESET_STREAM frames in any state due to delayed delivery of packets carrying them.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P3-0003")]
public sealed class REQ_QUIC_RFC9000_S3P3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P3-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceiveSideAcceptsDelayedStateChangingFramesAfterDataRecvd()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, streamData: [0x11, 0x22], offset: 0),
            out QuicStreamFrame finalFrame));

        Assert.True(state.TryReceiveStreamFrame(finalFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot dataRecvdSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, dataRecvdSnapshot.ReceiveState);
        Assert.True(dataRecvdSnapshot.HasFinalSize);
        Assert.Equal(2UL, dataRecvdSnapshot.FinalSize);

        Assert.True(state.TryReceiveStreamFrame(finalFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamDataBlockedFrame(
            new QuicStreamDataBlockedFrame(streamId: 1, maximumStreamData: 2),
            out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x42, finalSize: 2),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(18UL, maxDataFrame.MaximumData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot resetSnapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, resetSnapshot.ReceiveState);
        Assert.True(resetSnapshot.HasFinalSize);
        Assert.Equal(2UL, resetSnapshot.FinalSize);
    }
}

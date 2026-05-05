namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P9-0006")]
public sealed class REQ_QUIC_RFC9000_S19P9_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveFinalSizeFrames_AccountsTerminalStreamsAgainstTheConnectionLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 5,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x11, finalSize: 3),
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, errorCode);
        Assert.Equal(3UL, state.ConnectionAccountedBytesReceived);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot terminalSnapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, terminalSnapshot.ReceiveState);
        Assert.True(terminalSnapshot.HasFinalSize);
        Assert.Equal(3UL, terminalSnapshot.FinalSize);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, streamData: [0x22, 0x23], offset: 0),
            out QuicStreamFrame finFrame));
        Assert.True(state.TryReceiveStreamFrame(finFrame, out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(5UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedResetStreamFinalSizeViolationClosesWithFlowControlError()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
                connectionReceiveLimit: 5,
                peerBidirectionalReceiveLimit: 8);

        QuicConnectionTransitionResult accepted = QuicStreamControlFrameTestSupport.ReceiveProtectedApplicationPayload(
            runtime,
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, streamData: [0x10, 0x11, 0x12], offset: 0),
            nowTicks: 20);

        Assert.True(accepted.StateChanged);
        Assert.Equal(3UL, runtime.StreamRegistry.Bookkeeping.ConnectionAccountedBytesReceived);

        QuicConnectionTransitionResult rejected = QuicStreamControlFrameTestSupport.ReceiveProtectedApplicationPayload(
            runtime,
            QuicFrameTestData.BuildResetStreamFrame(
                new QuicResetStreamFrame(streamId: 5, applicationProtocolErrorCode: 0x44, finalSize: 3)),
            nowTicks: 21);

        QuicS19P9MaxDataFrameTestSupport.AssertLocalFlowControlClose(
            runtime,
            rejected,
            triggeringFrameType: QuicS19P9MaxDataFrameTestSupport.ResetStreamFrameType);
        Assert.Equal(3UL, runtime.StreamRegistry.Bookkeeping.ConnectionAccountedBytesReceived);
    }
}

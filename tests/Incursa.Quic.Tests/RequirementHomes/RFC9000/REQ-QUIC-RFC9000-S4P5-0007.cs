namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0007">If a RESET_STREAM or STREAM frame is received indicating a change in the final size for the stream, an endpoint SHOULD respond with an error of type FINAL_SIZE_ERROR.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P5-0007")]
public sealed class REQ_QUIC_RFC9000_S4P5_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_RejectsFinalSizeRegressionAfterHigherOffsetData()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        ulong streamId = 1;
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, streamId, [0xAA, 0xBB], offset: 4),
            out QuicStreamFrame leadingFrame));
        Assert.True(state.TryReceiveStreamFrame(leadingFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(2UL, snapshot.AccountedBytesReceived);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId, [0xCC], offset: 0),
            out QuicStreamFrame regressionFrame));
        Assert.False(state.TryReceiveStreamFrame(regressionFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out snapshot));
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(2UL, snapshot.AccountedBytesReceived);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveResetStreamFrame_RejectsFinalSizeRegressionAfterHigherOffsetData()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        ulong streamId = 1;
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, streamId, [0xAA, 0xBB], offset: 4),
            out QuicStreamFrame leadingFrame));
        Assert.True(state.TryReceiveStreamFrame(leadingFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: streamId, applicationProtocolErrorCode: 0x99, finalSize: 1),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(2UL, snapshot.AccountedBytesReceived);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);
    }
}

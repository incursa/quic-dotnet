namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P2-0003")]
public sealed class REQ_QUIC_RFC9000_S3P2_0003
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0003">The receiving part of a stream initiated by a peer MUST be created when the first STREAM, STREAM_DATA_BLOCKED, or RESET_STREAM frame is received for that stream.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_CreatesPeerInitiatedReceivingPartOnFirstFrame()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x08, streamId: 3, [0xBB]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(3, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.None, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_RejectsPeerInitiatedReceivingPartPastIncomingLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16,
            incomingUnidirectionalStreamLimit: 1);

        ulong streamId = 7;
        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x08, streamId, [0xCC]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(streamId, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveResetStreamFrame_CreatesPeerInitiatedReceivingPartOnFirstResetStreamFrame()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        QuicResetStreamFrame resetStreamFrame = new(3, applicationErrorCode: 0xCC, finalSize: 0);

        Assert.True(state.TryReceiveResetStreamFrame(resetStreamFrame, out QuicMaxDataFrame maxDataFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);

        Assert.True(state.TryGetStreamSnapshot(3, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.None, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
        Assert.Equal(0UL, snapshot.ReceiveFinalSize);
    }
}

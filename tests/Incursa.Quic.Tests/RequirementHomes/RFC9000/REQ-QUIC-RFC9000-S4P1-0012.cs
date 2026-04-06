namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0012">A receiver MUST close the connection with an error of type FLOW_CONTROL_ERROR if the sender violates the advertised connection or stream data limits.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P1-0012")]
public sealed class REQ_QUIC_RFC9000_S4P1_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_ClosesOnConnectionAndStreamFlowControlViolations()
    {
        QuicConnectionStreamState limitedStreams = QuicConnectionStreamStateTestHelpers.CreateState(incomingBidirectionalStreamLimit: 1);

        byte[] overLimitPacket = QuicStreamTestData.BuildStreamFrame(0x08, streamId: 5, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(overLimitPacket, out QuicStreamFrame overLimitFrame));
        Assert.False(limitedStreams.TryReceiveStreamFrame(overLimitFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);

        QuicConnectionStreamState limitedCredit = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalReceiveLimit: 3,
            connectionReceiveLimit: 3);

        byte[] initialPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x10, 0x11], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(initialPacket, out QuicStreamFrame initialFrame));
        Assert.True(limitedCredit.TryReceiveStreamFrame(initialFrame, out errorCode));
        Assert.Equal(default, errorCode);

        byte[] tooLargePacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x12, 0x13], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(tooLargePacket, out QuicStreamFrame tooLargeFrame));
        Assert.False(limitedCredit.TryReceiveStreamFrame(tooLargeFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);

        QuicConnectionStreamState finalSizeState = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalReceiveLimit: 8,
            connectionReceiveLimit: 8);

        byte[] finPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, streamData: [0x01, 0x02], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(finPacket, out QuicStreamFrame finFrame));
        Assert.True(finalSizeState.TryReceiveStreamFrame(finFrame, out errorCode));
        Assert.Equal(default, errorCode);

        byte[] changedFinalPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, streamData: [0x03], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(changedFinalPacket, out QuicStreamFrame changedFinalFrame));
        Assert.False(finalSizeState.TryReceiveStreamFrame(changedFinalFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
    }
}

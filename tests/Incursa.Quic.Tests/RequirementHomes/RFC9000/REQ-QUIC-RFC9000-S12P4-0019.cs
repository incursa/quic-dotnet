namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0019">That is, a valid frame MUST NOT cause undesirable side effects or errors when received more than once.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0019")]
public sealed class REQ_QUIC_RFC9000_S12P4_0019
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0019">That is, a valid frame MUST NOT cause undesirable side effects or errors when received more than once.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0019")]
    public void TryParseSelectedFrames_ReturnsTheSameResultsWhenReceivedMoreThanOnce()
    {
        byte[] pingFrame = QuicFrameTestData.BuildPingFrame();
        Assert.True(QuicFrameCodec.TryParsePingFrame(pingFrame, out int firstPingConsumed));
        Assert.True(QuicFrameCodec.TryParsePingFrame(pingFrame, out int secondPingConsumed));
        Assert.Equal(firstPingConsumed, secondPingConsumed);
        Assert.Equal(pingFrame.Length, firstPingConsumed);

        QuicAckFrame ackFrame = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 0x21,
            AckDelay = 0x05,
            FirstAckRange = 0x00,
        };

        byte[] encodedAckFrame = QuicFrameTestData.BuildAckFrame(ackFrame);
        Assert.True(QuicFrameCodec.TryParseAckFrame(encodedAckFrame, out QuicAckFrame firstParsedAckFrame, out int firstAckConsumed));
        Assert.True(QuicFrameCodec.TryParseAckFrame(encodedAckFrame, out QuicAckFrame secondParsedAckFrame, out int secondAckConsumed));
        Assert.Equal(firstAckConsumed, secondAckConsumed);
        Assert.Equal(firstParsedAckFrame.FrameType, secondParsedAckFrame.FrameType);
        Assert.Equal(firstParsedAckFrame.LargestAcknowledged, secondParsedAckFrame.LargestAcknowledged);
        Assert.Equal(firstParsedAckFrame.AckDelay, secondParsedAckFrame.AckDelay);
        Assert.Equal(firstParsedAckFrame.FirstAckRange, secondParsedAckFrame.FirstAckRange);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0019">That is, a valid frame MUST NOT cause undesirable side effects or errors when received more than once.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0019")]
    public void TryParseSelectedFrames_RejectsMalformedFramesConsistently()
    {
        byte[] truncatedConnectionClose = QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(QuicTransportErrorCode.ProtocolViolation, triggeringFrameType: 0x02, reasonPhrase: [0x6F, 0x6B]))[..^1];

        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(truncatedConnectionClose, out _, out _));
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(truncatedConnectionClose, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0019">That is, a valid frame MUST NOT cause undesirable side effects or errors when received more than once.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0019")]
    public void TryParseSelectedFrames_HandlesRepeatedReceiptOfTheShortestValidFrame()
    {
        byte[] paddingFrame = QuicFrameTestData.BuildPaddingFrame();

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(paddingFrame, out int firstPaddingConsumed));
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(paddingFrame, out int secondPaddingConsumed));
        Assert.Equal(1, firstPaddingConsumed);
        Assert.Equal(firstPaddingConsumed, secondPaddingConsumed);
    }
}

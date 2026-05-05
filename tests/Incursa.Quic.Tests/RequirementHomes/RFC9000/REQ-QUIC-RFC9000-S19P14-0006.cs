namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
public sealed class REQ_QUIC_RFC9000_S19P14_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamsBlockedFrame_ParsesTheRequiredMaximumStreamsField()
    {
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(
            isBidirectional: false,
            maximumStreams: 0x5678);

        QuicS19P14StreamsBlockedFrameTestSupport.AssertParses(
            encoded,
            expectedIsBidirectional: false,
            expectedMaximumStreams: 0x5678);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamsBlockedFrame_RejectsMissingMaximumStreamsField()
    {
        byte[] encoded = [QuicS19P14StreamsBlockedFrameTestSupport.StreamsBlockedBidirectionalFrameType];

        QuicS19P14StreamsBlockedFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamsBlockedFrame_ConsumesOnlyTheStreamsBlockedFrame()
    {
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrameWithTrailingFrame(
            isBidirectional: true,
            maximumStreams: 0x80);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(
            encoded,
            out QuicStreamsBlockedFrame frame,
            out int bytesConsumed));

        Assert.True(frame.IsBidirectional);
        Assert.Equal(0x80UL, frame.MaximumStreams);
        Assert.Equal(encoded.Length - QuicFrameTestData.BuildPingFrame().Length, bytesConsumed);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
public sealed class REQ_QUIC_RFC9000_S19P13_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamDataBlockedFrame_ParsesBothRequiredFields()
    {
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrame(
            streamId: 0x1234,
            maximumStreamData: 0x5678);

        QuicS19P13StreamDataBlockedFrameTestSupport.AssertParses(
            encoded,
            expectedStreamId: 0x1234,
            expectedMaximumStreamData: 0x5678);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamDataBlockedFrame_RejectsMissingMaximumStreamDataField()
    {
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrameWithTruncatedEncodedStreamId([0x04]);

        QuicS19P13StreamDataBlockedFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamDataBlockedFrame_ConsumesOnlyTheStreamDataBlockedFrame()
    {
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrameWithTrailingFrame(
            streamId: 0x40,
            maximumStreamData: 0x80);

        Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(
            encoded,
            out QuicStreamDataBlockedFrame frame,
            out int bytesConsumed));

        Assert.Equal(0x40UL, frame.StreamId);
        Assert.Equal(0x80UL, frame.MaximumStreamData);
        Assert.Equal(encoded.Length - QuicFrameTestData.BuildPingFrame().Length, bytesConsumed);
    }
}

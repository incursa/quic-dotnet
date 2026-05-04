namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0014")]
public sealed class REQ_QUIC_RFC9000_S19P8_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_ReportsTheByteOffsetForFrameData()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0E,
            streamId: 0x04,
            streamData: [0xAA, 0xBB],
            offset: 0x40);

        Assert.True(frame.HasOffset);
        Assert.Equal(0x40UL, frame.Offset);
        Assert.Equal(2, frame.StreamDataLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsMissingOffsetFieldWhenOffBitIsSet()
    {
        QuicS19P8StreamFrameTestSupport.AssertRejects([0x0C, 0x00]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_ReportsExplicitZeroOffset()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0E,
            streamId: 0x04,
            streamData: [],
            offset: 0);

        Assert.True(frame.HasOffset);
        Assert.Equal(0UL, frame.Offset);
    }
}

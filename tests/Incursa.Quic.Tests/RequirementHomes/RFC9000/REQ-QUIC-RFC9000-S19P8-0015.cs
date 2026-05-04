namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0015")]
public sealed class REQ_QUIC_RFC9000_S19P8_0015
{
    [Theory]
    [InlineData((byte)0x0C)]
    [InlineData((byte)0x0D)]
    [InlineData((byte)0x0E)]
    [InlineData((byte)0x0F)]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_OffsetFieldIsPresentWhenOffBitIsSet(byte frameType)
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType,
            streamId: 0x04,
            streamData: [0xAA],
            offset: 0x21);

        Assert.True(frame.HasOffset);
        Assert.Equal(0x21UL, frame.Offset);
    }
}

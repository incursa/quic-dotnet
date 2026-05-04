namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0017")]
public sealed class REQ_QUIC_RFC9000_S19P8_0017
{
    [Theory]
    [InlineData((byte)0x0A)]
    [InlineData((byte)0x0B)]
    [InlineData((byte)0x0E)]
    [InlineData((byte)0x0F)]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_LengthFieldIsPresentWhenLenBitIsSet(byte frameType)
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType,
            streamId: 0x04,
            streamData: [0xAA],
            offset: (frameType & QuicStreamFrameBits.OffsetBitMask) != 0 ? 1UL : 0UL);

        Assert.True(frame.HasLength);
        Assert.Equal(1UL, frame.Length);
    }
}

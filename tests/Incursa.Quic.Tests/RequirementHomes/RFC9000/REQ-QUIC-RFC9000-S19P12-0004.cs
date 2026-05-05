namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
public sealed class REQ_QUIC_RFC9000_S19P12_0004
{
    [Theory]
    [InlineData(0x3FUL, 1)]
    [InlineData(0x40UL, 2)]
    [InlineData(0x3FFFUL, 2)]
    [InlineData(0x4000UL, 4)]
    [InlineData(0x3FFF_FFFFUL, 4)]
    [InlineData(0x4000_0000UL, 8)]
    [InlineData(QuicVariableLengthInteger.MaxValue, 8)]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseDataBlockedFrame_AcceptsAllMaximumDataVarintLengths(
        ulong maximumData,
        int expectedMaximumDataFieldLength)
    {
        byte[] encoded = QuicS19P12DataBlockedFrameTestSupport.BuildDataBlockedFrame(maximumData);

        Assert.True(QuicFrameCodec.TryParseDataBlockedFrame(
            encoded,
            out QuicDataBlockedFrame frame,
            out int bytesConsumed));

        Assert.Equal(maximumData, frame.MaximumData);
        Assert.Equal(1 + expectedMaximumDataFieldLength, bytesConsumed);
        QuicS19P12DataBlockedFrameTestSupport.AssertFormats(frame, encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseDataBlockedFrame_RejectsTruncatedMaximumDataVarints()
    {
        byte[][] truncatedMaximumDataFields =
        [
            [0x40],
            [0x80, 0x00, 0x00],
            [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];

        foreach (byte[] encodedMaximumData in truncatedMaximumDataFields)
        {
            byte[] encoded = QuicS19P12DataBlockedFrameTestSupport.BuildDataBlockedFrameWithEncodedMaximumData(encodedMaximumData);

            QuicS19P12DataBlockedFrameTestSupport.AssertRejects(encoded);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatDataBlockedFrame_RejectsMaximumDataAboveTheVarintRange()
    {
        QuicDataBlockedFrame frame = new(QuicVariableLengthInteger.MaxValue + 1);
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryFormatDataBlockedFrame(frame, destination, out _));
    }
}

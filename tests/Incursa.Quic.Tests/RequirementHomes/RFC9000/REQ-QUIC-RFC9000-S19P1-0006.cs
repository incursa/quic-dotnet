namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P1-0006")]
public sealed class REQ_QUIC_RFC9000_S19P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPaddingFrame_EncodesTypeAsVarintValue00()
    {
        Span<byte> destination = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(destination, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.Equal((byte)0x00, destination[0]);

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(destination[..bytesWritten], out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParsePaddingFrame_RejectsNonPaddingTypeValue()
    {
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([0x01], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParsePaddingFrame_RejectsNonMinimalVarintEncodingOfType00()
    {
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([0x40, 0x00], out _));
    }
}

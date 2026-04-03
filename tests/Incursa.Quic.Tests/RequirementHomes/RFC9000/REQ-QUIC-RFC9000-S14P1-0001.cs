namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P1-0001")]
public sealed class REQ_QUIC_RFC9000_S14P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatVersion1InitialDatagramPadding_WritesPaddingFramesUpToTheRFCMinimum()
    {
        Span<byte> destination = stackalloc byte[13];

        Assert.True(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(
            1187,
            destination,
            out int bytesWritten));

        Assert.Equal(13, bytesWritten);
        Assert.All(destination[..bytesWritten].ToArray(), static value => Assert.Equal(0, value));

        for (int index = 0; index < bytesWritten; index++)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(destination[index..bytesWritten], out int bytesConsumed));
            Assert.Equal(1, bytesConsumed);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatVersion1InitialDatagramPadding_RejectsNegativePayloadLengths()
    {
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(-1, stackalloc byte[1], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryFormatVersion1InitialDatagramPadding_AllowsZeroPaddingAtTheMinimumPayloadSize()
    {
        Assert.True(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(
            1200,
            stackalloc byte[0],
            out int bytesWritten));

        Assert.Equal(0, bytesWritten);
    }
}

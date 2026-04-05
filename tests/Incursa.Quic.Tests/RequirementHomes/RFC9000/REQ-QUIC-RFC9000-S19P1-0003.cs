namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P1-0003")]
public sealed class REQ_QUIC_RFC9000_S19P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatVersion1InitialDatagramPadding_WritesTheMinimumPaddingNeededForAnInitialPacket()
    {
        Span<byte> destination = stackalloc byte[13];

        Assert.True(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(1187, destination, out int bytesWritten));
        Assert.Equal(13, bytesWritten);
        Assert.All(destination[..bytesWritten].ToArray(), static value => Assert.Equal(0, value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatVersion1InitialDatagramPadding_RejectsNegativeLengthsAndTooSmallDestinations()
    {
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(-1, stackalloc byte[1], out _));
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(1199, stackalloc byte[0], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryGetVersion1InitialDatagramPaddingLength_ReturnsZeroAtTheMinimumSizeBoundary()
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(1200, out int paddingLength));
        Assert.Equal(0, paddingLength);
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0004">Clients MUST ensure that UDP datagrams containing Initial packets have UDP payloads of at least 1200 bytes, adding PADDING frames as necessary.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
public sealed class REQ_QUIC_RFC9000_S8P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryGetVersion1InitialDatagramPaddingLength_UsesTheExactMinimumPayloadBoundary()
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(1200, out int paddingLength));

        Assert.Equal(0, paddingLength);
    }

    [Theory]
    [InlineData(1187, 13)]
    [InlineData(1199, 1)]
    [InlineData(1200, 0)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetVersion1InitialDatagramPaddingLength_ComputesTheRemainingPadding(
        int currentPayloadLength,
        int expectedPaddingLength)
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(
            currentPayloadLength,
            out int paddingLength));

        Assert.Equal(expectedPaddingLength, paddingLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGetVersion1InitialDatagramPaddingLength_RejectsNegativeCurrentPayloadLength()
    {
        Assert.False(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(-1, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatVersion1InitialDatagramPadding_RejectsNegativeLengthsAndShortDestinations()
    {
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(-1, stackalloc byte[1], out _));
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(1199, stackalloc byte[0], out _));
    }
}

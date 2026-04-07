namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0003">A server MUST expand the payload of all UDP datagrams carrying ack-eliciting Initial packets to at least the smallest allowed maximum datagram size of 1200 bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P1-0003")]
public sealed class REQ_QUIC_RFC9000_S14P1_0003
{
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
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatVersion1InitialDatagramPadding_WritesRepeatedPaddingFrames()
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
}

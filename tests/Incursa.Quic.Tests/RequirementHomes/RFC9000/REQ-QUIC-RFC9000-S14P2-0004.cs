namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0004">In the absence of these mechanisms, QUIC endpoints SHOULD NOT send datagrams larger than the smallest allowed maximum datagram size.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0004")]
public sealed class REQ_QUIC_RFC9000_S14P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetVersion1InitialDatagramPaddingLength_ComputesPaddingToTheMinimum()
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(1187, out int paddingLength));
        Assert.Equal(13, paddingLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetVersion1InitialDatagramPaddingLength_RejectsNegativePayloadLengths()
    {
        Assert.False(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(-1, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryGetVersion1InitialDatagramPaddingLength_AllowsPayloadsAtTheRFCMinimum()
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            out int paddingLength));

        Assert.Equal(0, paddingLength);
    }
}

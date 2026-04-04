namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P2-0005">Implementations MAY reduce the congestion window immediately upon entering a recovery period or use other mechanisms, such as Proportional Rate Reduction, to reduce the congestion window more gradually.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P3P2-0005")]
public sealed class REQ_QUIC_RFC9002_S7P3P2_0005
{
    [Theory]
    [InlineData(12_000UL, 7UL, 8UL, 2_400UL, 10_500UL)]
    [InlineData(1_000UL, 7UL, 8UL, 2_400UL, 2_400UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ComputeReducedCongestionWindowBytes_UsesAGentlerReductionFactorAndHonorsMinimumWindow(
        ulong congestionWindowBytes,
        ulong reductionNumerator,
        ulong reductionDenominator,
        ulong minimumCongestionWindowBytes,
        ulong expectedReducedCongestionWindowBytes)
    {
        Assert.Equal(expectedReducedCongestionWindowBytes, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
            congestionWindowBytes,
            reductionNumerator: reductionNumerator,
            reductionDenominator: reductionDenominator,
            minimumCongestionWindowBytes: minimumCongestionWindowBytes));
    }
}

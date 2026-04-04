namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP1-0001">kLossReductionFactor SHOULD be 0.5.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP1-0001")]
public sealed class REQ_QUIC_RFC9002_SBP1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ComputeReducedCongestionWindowBytes_UsesTheRecommendedLossReductionFactor()
    {
        ulong minimumWindowBytes = QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(1_200);

        Assert.Equal(1UL, QuicCongestionControlState.RecommendedLossReductionNumerator);
        Assert.Equal(2UL, QuicCongestionControlState.RecommendedLossReductionDenominator);
        Assert.Equal(6_000UL, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
            congestionWindowBytes: 12_000,
            reductionNumerator: QuicCongestionControlState.RecommendedLossReductionNumerator,
            reductionDenominator: QuicCongestionControlState.RecommendedLossReductionDenominator,
            minimumCongestionWindowBytes: minimumWindowBytes));
    }
}

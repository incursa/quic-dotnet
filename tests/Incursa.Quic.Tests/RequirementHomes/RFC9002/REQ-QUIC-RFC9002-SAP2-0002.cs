namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP2-0002")]
public sealed class REQ_QUIC_RFC9002_SAP2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecommendedTimeThreshold_UsesNineOverEight()
    {
        Assert.Equal(9UL, QuicRecoveryTiming.RecommendedTimeThresholdNumerator);
        Assert.Equal(8UL, QuicRecoveryTiming.RecommendedTimeThresholdDenominator);
    }
}

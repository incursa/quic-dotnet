namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP2-0003">kGranularity SHOULD be 1 millisecond.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP2-0003")]
public sealed class REQ_QUIC_RFC9002_SAP2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecommendedTimerGranularity_UsesOneMillisecond()
    {
        Assert.Equal(1_000UL, QuicRecoveryTiming.RecommendedTimerGranularityMicros);
        Assert.Equal(1_000UL, QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: 0,
            smoothedRttMicros: 0));
    }
}

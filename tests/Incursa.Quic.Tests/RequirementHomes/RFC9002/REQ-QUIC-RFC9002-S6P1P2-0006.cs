namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0006">The RECOMMENDED timer granularity, kGranularity, SHOULD be 1 millisecond.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P1P2-0006")]
public sealed class REQ_QUIC_RFC9002_S6P1P2_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecommendedTimerGranularity_UsesOneMillisecond()
    {
        Assert.Equal(1_000UL, QuicRecoveryTiming.RecommendedTimerGranularityMicros);
    }
}

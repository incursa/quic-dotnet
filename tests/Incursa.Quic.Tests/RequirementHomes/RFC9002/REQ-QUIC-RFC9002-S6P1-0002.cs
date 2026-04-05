namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1-0002">Implementations with adaptive time thresholds MAY start with smaller initial reordering thresholds to minimize recovery latency.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P1-0002")]
public sealed class REQ_QUIC_RFC9002_S6P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ComputeLossDelayMicros_AcceptsASmallerAdaptiveThreshold()
    {
        ulong recommendedLossDelayMicros = QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: 600,
            smoothedRttMicros: 800,
            timeThresholdNumerator: QuicRecoveryTiming.RecommendedTimeThresholdNumerator,
            timeThresholdDenominator: QuicRecoveryTiming.RecommendedTimeThresholdDenominator,
            timerGranularityMicros: 250);

        ulong adaptiveLossDelayMicros = QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: 600,
            smoothedRttMicros: 800,
            timeThresholdNumerator: 9,
            timeThresholdDenominator: 10,
            timerGranularityMicros: 250);

        Assert.Equal(900UL, recommendedLossDelayMicros);
        Assert.Equal(720UL, adaptiveLossDelayMicros);
        Assert.True(adaptiveLossDelayMicros < recommendedLossDelayMicros);
    }
}

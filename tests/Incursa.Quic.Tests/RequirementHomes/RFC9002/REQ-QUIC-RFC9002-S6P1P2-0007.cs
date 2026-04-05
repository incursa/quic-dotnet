namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0007">Implementations MAY experiment with absolute thresholds, thresholds from previous connections, adaptive thresholds, or RTT variation.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P1P2-0007")]
public sealed class REQ_QUIC_RFC9002_S6P1P2_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ComputeLossDelayMicros_AcceptsAlternativeThresholdParameters()
    {
        Assert.Equal(1_000UL, QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: 600,
            smoothedRttMicros: 800,
            timeThresholdNumerator: 10,
            timeThresholdDenominator: 8,
            timerGranularityMicros: 250));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ComputeLossDelayMicros_RejectsAZeroTimeThresholdDenominator()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.ComputeLossDelayMicros(
                latestRttMicros: 600,
                smoothedRttMicros: 800,
                timeThresholdDenominator: 0,
                timerGranularityMicros: 250));

        Assert.Equal("timeThresholdDenominator", exception.ParamName);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ComputeLossDelayMicros_UsesTheGranularityFloorForAnAlternativeThreshold()
    {
        Assert.Equal(250UL, QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: 1,
            smoothedRttMicros: 1,
            timeThresholdNumerator: 1,
            timeThresholdDenominator: 2,
            timerGranularityMicros: 250));
    }
}

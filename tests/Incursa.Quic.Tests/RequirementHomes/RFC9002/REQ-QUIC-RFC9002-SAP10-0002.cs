namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP10-0002">`DetectAndRemoveLostPackets` MUST compute `loss_delay` as `kTimeThreshold` times the larger of `latest_rtt` and `smoothed_rtt`, and not let `loss_delay` fall below `kGranularity`.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP10-0002")]
public sealed class REQ_QUIC_RFC9002_SAP10_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ComputeLossDelayMicros_UsesTheLargerRttSampleForTheLossDelay()
    {
        Assert.Equal(1_350UL, QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: 1_200,
            smoothedRttMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ComputeLossDelayMicros_RejectsAZeroTimerGranularity()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.ComputeLossDelayMicros(
                latestRttMicros: 800,
                smoothedRttMicros: 1_000,
                timerGranularityMicros: 0));

        Assert.Equal("timerGranularityMicros", exception.ParamName);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ComputeLossDelayMicros_BoundsTheLossDelayByTimerGranularity()
    {
        Assert.Equal(1_000UL, QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: 1,
            smoothedRttMicros: 1));
    }
}

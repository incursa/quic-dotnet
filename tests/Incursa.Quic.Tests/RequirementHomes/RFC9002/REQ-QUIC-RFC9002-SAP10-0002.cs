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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ComputeLossDelayMicros_FuzzesRttThresholdAndGranularityFloor()
    {
        for (uint sampleIndex = 0; sampleIndex < 192; sampleIndex++)
        {
            ulong latestRttMicros = sampleIndex * 97 % 5_000;
            ulong smoothedRttMicros = sampleIndex * 131 % 5_000;
            ulong timerGranularityMicros = 1 + (sampleIndex * 17 % 2_000);
            ulong referenceRttMicros = Math.Max(latestRttMicros, smoothedRttMicros);
            ulong expectedLossDelayMicros = Math.Max((referenceRttMicros * 9) / 8, timerGranularityMicros);

            ulong actualLossDelayMicros = QuicRecoveryTiming.ComputeLossDelayMicros(
                latestRttMicros,
                smoothedRttMicros,
                timerGranularityMicros: timerGranularityMicros);

            Assert.Equal(expectedLossDelayMicros, actualLossDelayMicros);
            Assert.True(actualLossDelayMicros >= timerGranularityMicros);
        }
    }
}

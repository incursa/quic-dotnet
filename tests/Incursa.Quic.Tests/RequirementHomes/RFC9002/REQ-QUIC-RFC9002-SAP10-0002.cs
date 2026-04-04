namespace Incursa.Quic.Tests;

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

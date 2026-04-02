namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P1P2-0002")]
public sealed class REQ_QUIC_RFC9002_S6P1P2_0002
{
    public static TheoryData<LossDelayThresholdCase> LossDelayThresholdCases => new()
    {
        new(1, 1, 1_000),
        new(889, 889, 1_000),
        new(900, 900, 1_012),
    };

    [Theory]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0002")]
    [MemberData(nameof(LossDelayThresholdCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ComputeLossDelayMicros_BoundsTheTimeThresholdByTimerGranularity(LossDelayThresholdCase scenario)
    {
        Assert.Equal(scenario.ExpectedLossDelayMicros, QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: scenario.LatestRttMicros,
            smoothedRttMicros: scenario.SmoothedRttMicros));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0002")]
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

    public sealed record LossDelayThresholdCase(
        ulong LatestRttMicros,
        ulong SmoothedRttMicros,
        ulong ExpectedLossDelayMicros);
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P1P2-0005")]
public sealed class REQ_QUIC_RFC9002_S6P1P2_0005
{
    public static TheoryData<RecommendedMultiplierCase> RecommendedMultiplierCases => new()
    {
        new(8, 8, 9),
        new(9, 9, 10),
    };

    [Theory]
    [MemberData(nameof(RecommendedMultiplierCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ComputeLossDelayMicros_UsesTheRecommendedNineEighthsMultiplier(RecommendedMultiplierCase scenario)
    {
        Assert.Equal(scenario.ExpectedLossDelayMicros, QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: scenario.LatestRttMicros,
            smoothedRttMicros: scenario.SmoothedRttMicros,
            timerGranularityMicros: 1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ComputeLossDelayMicros_RejectsAZeroTimeThresholdNumerator()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.ComputeLossDelayMicros(
                latestRttMicros: 8,
                smoothedRttMicros: 8,
                timeThresholdNumerator: 0,
                timerGranularityMicros: 1));

        Assert.Equal("timeThresholdNumerator", exception.ParamName);
    }

    public sealed record RecommendedMultiplierCase(
        ulong LatestRttMicros,
        ulong SmoothedRttMicros,
        ulong ExpectedLossDelayMicros);
}

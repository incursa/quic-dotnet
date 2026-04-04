namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0003">The time threshold MUST be max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity).</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P1P2-0003")]
public sealed class REQ_QUIC_RFC9002_S6P1P2_0003
{
    public static TheoryData<LossDelayFormulaCase> LossDelayFormulaCases => new()
    {
        new(800, 1_000, 1_125),
        new(1_000, 1_000, 1_125),
        new(1_200, 1_000, 1_350),
    };

    [Theory]
    [MemberData(nameof(LossDelayFormulaCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ComputeLossDelayMicros_ComputesTheTimeThresholdFromRttAndGranularity(LossDelayFormulaCase scenario)
    {
        Assert.Equal(scenario.ExpectedLossDelayMicros, QuicRecoveryTiming.ComputeLossDelayMicros(
            latestRttMicros: scenario.LatestRttMicros,
            smoothedRttMicros: scenario.SmoothedRttMicros));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ComputeLossDelayMicros_RejectsAZeroTimeThresholdDenominator()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.ComputeLossDelayMicros(
                latestRttMicros: 800,
                smoothedRttMicros: 1_000,
                timeThresholdDenominator: 0));

        Assert.Equal("timeThresholdDenominator", exception.ParamName);
    }

    public sealed record LossDelayFormulaCase(
        ulong LatestRttMicros,
        ulong SmoothedRttMicros,
        ulong ExpectedLossDelayMicros);
}

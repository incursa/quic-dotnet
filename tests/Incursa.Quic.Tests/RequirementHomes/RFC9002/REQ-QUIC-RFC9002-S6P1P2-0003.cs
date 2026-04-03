namespace Incursa.Quic.Tests;

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

    public sealed record LossDelayFormulaCase(
        ulong LatestRttMicros,
        ulong SmoothedRttMicros,
        ulong ExpectedLossDelayMicros);
}

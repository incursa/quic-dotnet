namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0001">Once a later packet within the same packet number space has been acknowledged, an endpoint SHOULD declare an earlier packet lost if it was sent a threshold amount of time in the past.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P1P2-0001")]
public sealed class REQ_QUIC_RFC9002_S6P1P2_0001
{
    public static TheoryData<RemainingLossDelayCase> RemainingLossDelayCases => new()
    {
        new(1_000, 2_124, 800, 1_000, 1),
        new(1_000, 2_125, 800, 1_000, 0),
        new(5_000, 5_999, 1, 1, 1),
        new(5_000, 6_000, 1, 1, 0),
    };

    [Theory]
    [MemberData(nameof(RemainingLossDelayCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeRemainingLossDelayMicros_ReachesZeroAtTheLossDeadline(RemainingLossDelayCase scenario)
    {
        Assert.True(QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
            packetSentAtMicros: scenario.PacketSentAtMicros,
            nowMicros: scenario.NowMicros,
            latestRttMicros: scenario.LatestRttMicros,
            smoothedRttMicros: scenario.SmoothedRttMicros,
            out ulong remainingLossDelayMicros));

        Assert.Equal(scenario.ExpectedRemainingLossDelayMicros, remainingLossDelayMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeRemainingLossDelayMicros_RejectsAZeroTimerGranularity()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
                packetSentAtMicros: 1_000,
                nowMicros: 2_000,
                latestRttMicros: 800,
                smoothedRttMicros: 1_000,
                out _,
                timerGranularityMicros: 0));

        Assert.Equal("timerGranularityMicros", exception.ParamName);
    }

    public sealed record RemainingLossDelayCase(
        ulong PacketSentAtMicros,
        ulong NowMicros,
        ulong LatestRttMicros,
        ulong SmoothedRttMicros,
        ulong ExpectedRemainingLossDelayMicros);
}

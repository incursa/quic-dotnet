namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0004">If packets sent prior to the largest acknowledged packet cannot yet be declared lost, a timer SHOULD be set for the remaining time.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P1P2-0004")]
public sealed class REQ_QUIC_RFC9002_S6P1P2_0004
{
    public static TheoryData<RemainingTimerCase> RemainingTimerCases => new()
    {
        new(1_000, 2_124, 800, 1_000, 1),
        new(ulong.MaxValue - 100, ulong.MaxValue - 1, 1_000, 1_000, 1),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryComputeRemainingLossDelayMicros_SchedulesTheRemainingTimeBeforeLoss()
    {
        Assert.True(QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
            packetSentAtMicros: 1_000,
            nowMicros: 2_000,
            latestRttMicros: 800,
            smoothedRttMicros: 1_000,
            out ulong remainingLossDelayMicros));

        Assert.Equal(125UL, remainingLossDelayMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeRemainingLossDelayMicros_RejectsAZeroTimeThresholdNumerator()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
                packetSentAtMicros: 1_000,
                nowMicros: 2_000,
                latestRttMicros: 800,
                smoothedRttMicros: 1_000,
                out _,
                timeThresholdNumerator: 0));

        Assert.Equal("timeThresholdNumerator", exception.ParamName);
    }

    [Theory]
    [MemberData(nameof(RemainingTimerCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeRemainingLossDelayMicros_ReportsTheRemainingTimerAtTheBoundary(RemainingTimerCase scenario)
    {
        Assert.True(QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
            packetSentAtMicros: scenario.PacketSentAtMicros,
            nowMicros: scenario.NowMicros,
            latestRttMicros: scenario.LatestRttMicros,
            smoothedRttMicros: scenario.SmoothedRttMicros,
            out ulong remainingLossDelayMicros));

        Assert.Equal(scenario.ExpectedRemainingLossDelayMicros, remainingLossDelayMicros);
    }

    public sealed record RemainingTimerCase(
        ulong PacketSentAtMicros,
        ulong NowMicros,
        ulong LatestRttMicros,
        ulong SmoothedRttMicros,
        ulong ExpectedRemainingLossDelayMicros);
}

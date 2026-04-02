namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P1P2-0001")]
[Requirement("REQ-QUIC-RFC9002-S6P1P2-0004")]
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
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0004")]
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

    public sealed record RemainingLossDelayCase(
        ulong PacketSentAtMicros,
        ulong NowMicros,
        ulong LatestRttMicros,
        ulong SmoothedRttMicros,
        ulong ExpectedRemainingLossDelayMicros);
}

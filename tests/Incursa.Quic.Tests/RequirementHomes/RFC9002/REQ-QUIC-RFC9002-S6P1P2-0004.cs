namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P1P2-0004")]
public sealed class REQ_QUIC_RFC9002_S6P1P2_0004
{
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
}

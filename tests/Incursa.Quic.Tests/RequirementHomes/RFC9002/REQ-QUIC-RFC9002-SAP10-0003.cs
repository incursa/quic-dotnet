namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP10-0003")]
public sealed class REQ_QUIC_RFC9002_SAP10_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryComputeRemainingLossDelayMicros_SchedulesFutureLossMarkingForPacketsThatAreNotYetLost()
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
    [Trait("Category", "Negative")]
    public void CanDeclarePacketLost_ReturnsFalseWhenThePacketIsNotFarEnoughBehindTheLargestAcknowledgedPacket()
    {
        Assert.False(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged: false,
            packetInFlight: true,
            packetNumber: 11,
            largestAcknowledgedPacketNumber: 11));
    }

    [Theory]
    [InlineData(1_000UL, 2_125UL, 800UL, 1_000UL)]
    [InlineData(5_000UL, 6_000UL, 1UL, 1UL)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeRemainingLossDelayMicros_ReachesZeroAtTheLossDeadline(
        ulong packetSentAtMicros,
        ulong nowMicros,
        ulong latestRttMicros,
        ulong smoothedRttMicros)
    {
        Assert.True(QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
            packetSentAtMicros,
            nowMicros,
            latestRttMicros,
            smoothedRttMicros,
            out ulong remainingLossDelayMicros));

        Assert.Equal(0UL, remainingLossDelayMicros);
    }
}

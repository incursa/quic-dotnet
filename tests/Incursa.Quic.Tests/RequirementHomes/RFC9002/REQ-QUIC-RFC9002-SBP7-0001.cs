namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP7-0001")]
public sealed class REQ_QUIC_RFC9002_SBP7_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessEcn_TreatsAnIncreasingCeCountAsCongestion()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 3_000,
            pathValidated: true));

        Assert.Equal(3_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessEcn_IgnoresAnUnchangedCeCount()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 0,
            largestAcknowledgedPacketSentAtMicros: 3_000,
            pathValidated: true));

        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.Equal(13_200UL, state.BytesInFlightBytes);
    }
}

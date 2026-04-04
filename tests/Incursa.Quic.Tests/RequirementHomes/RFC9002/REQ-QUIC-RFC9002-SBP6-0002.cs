namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP6-0002")]
public sealed class REQ_QUIC_RFC9002_SBP6_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_EntersRecoveryAndReducesTheWindowOnEligibleCongestionSignals()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterLoss_DoesNotChangeTheWindowForIneligibleSignals()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.False(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: false));

        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
    }
}

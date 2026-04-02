namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP5-0004")]
public sealed class REQ_QUIC_RFC9002_SBP5_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP5-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterAcknowledgedPacket_DoesNotGrowTheWindowForPacketsAcknowledgedDuringRecovery()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(1_000UL, state.RecoveryStartTimeMicros);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }
}

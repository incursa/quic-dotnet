namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP5-0004">On packet acknowledgment, the sender MUST NOT increase congestion_window for packets acknowledged during a recovery period.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP5-0004")]
public sealed class REQ_QUIC_RFC9002_SBP5_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterAcknowledgedPacket_GrowsTheWindowForPacketsAcknowledgedAfterRecoveryStarted()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.Equal(6_240UL, state.CongestionWindowBytes);
        Assert.Null(state.RecoveryStartTimeMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
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

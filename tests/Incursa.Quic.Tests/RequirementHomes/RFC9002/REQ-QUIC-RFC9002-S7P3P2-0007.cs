namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P2-0007">A recovery period MUST end and the sender enter congestion avoidance when a packet sent during the recovery period is acknowledged.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P3P2-0007")]
public sealed class REQ_QUIC_RFC9002_S7P3P2_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterAcknowledgedPacket_EntersCongestionAvoidanceWhenARecoveryPeriodPacketIsAcknowledged()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 3_000,
            packetInFlight: true));

        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.Equal(6_240UL, state.CongestionWindowBytes);
        Assert.True(state.IsInCongestionAvoidance);
    }
}

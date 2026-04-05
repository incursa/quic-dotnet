namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP6-0003">When a new congestion event is detected, the sender MAY send one packet to speed up loss recovery.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP6-0003")]
public sealed class REQ_QUIC_RFC9002_SBP6_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_AllowsOneProbePacketAfterEnteringRecovery()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.True(state.HasRecoveryStartTime);
        Assert.False(state.CanSend(1_200));
        Assert.True(state.CanSend(1_200, isProbePacket: true));

        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }
}

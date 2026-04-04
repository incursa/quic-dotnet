namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP5-0006">While in congestion avoidance, the sender MUST increase congestion_window by max_datagram_size multiplied by the acknowledged bytes and divided by congestion_window.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP5-0006")]
public sealed class REQ_QUIC_RFC9002_SBP5_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterAcknowledgedPacket_GrowsTheWindowProportionallyInCongestionAvoidance()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.Equal(6_240UL, state.CongestionWindowBytes);
    }
}

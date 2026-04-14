namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P8-0001">When bytes in flight is smaller than the congestion window and sending is not pacing limited, the congestion window SHOULD NOT be increased in either slow start or congestion avoidance.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P8-0001")]
public sealed class REQ_QUIC_RFC9002_S7P8_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterAcknowledgedPacket_LeavesTheWindowUnchangedWhenTheSenderIsNotPacingLimited()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: false));

        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.False(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterAcknowledgedPacket_GrowsTheWindowWhenTheSameStateIsPacingLimited()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: true));

        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.Equal(13_200UL, state.CongestionWindowBytes);
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P3-0001">A NewReno sender MUST be considered in congestion avoidance any time the congestion window is at or above the slow start threshold and not in a recovery period.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P3P3-0001")]
public sealed class REQ_QUIC_RFC9002_S7P3P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void Constructor_LeavesTheSenderInSlowStartBeforeAnyThresholdBoundaryIsReached()
    {
        QuicCongestionControlState state = new();

        Assert.True(state.IsInSlowStart);
        Assert.False(state.IsInCongestionAvoidance);
        Assert.False(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryRegisterAcknowledgedPacket_LeavesTheSenderInCongestionAvoidanceAtTheThresholdBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.True(state.HasRecoveryStartTime);
        Assert.True(state.IsInCongestionAvoidance);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true,
            applicationLimited: true));

        Assert.False(state.HasRecoveryStartTime);
        Assert.True(state.IsInCongestionAvoidance);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
    }
}

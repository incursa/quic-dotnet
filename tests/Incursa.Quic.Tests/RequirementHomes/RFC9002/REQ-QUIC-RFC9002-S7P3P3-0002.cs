namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P3-0002">A sender in congestion avoidance MUST limit the increase to the congestion window to at most one maximum datagram size for each congestion window that is acknowledged.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P3P3-0002")]
public sealed class REQ_QUIC_RFC9002_S7P3P3_0002
{
    [Theory]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    [InlineData(3_000UL, 6_600UL)]
    [InlineData(6_000UL, 7_200UL)]
    [InlineData(12_000UL, 8_400UL)]
    public void TryRegisterAcknowledgedPacket_GrowsTheCongestionWindowByOneDatagramPerCongestionWindowAcknowledged(
        ulong acknowledgedBytes,
        ulong expectedCongestionWindowBytes)
    {
        QuicCongestionControlState state = CreateCongestionAvoidanceState();

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: acknowledgedBytes,
            sentAtMicros: 2_000,
            packetInFlight: true,
            pacingLimited: true));

        Assert.Equal(expectedCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(12_000UL - acknowledgedBytes, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.True(state.IsInCongestionAvoidance);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryRegisterAcknowledgedPacket_DoesNotUseTheCongestionAvoidanceFormulaBeforeTheThresholdIsReached()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: true));

        Assert.Equal(13_200UL, state.CongestionWindowBytes);
        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.True(state.IsInSlowStart);
        Assert.False(state.IsInCongestionAvoidance);
    }

    private static QuicCongestionControlState CreateCongestionAvoidanceState()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.True(state.IsInCongestionAvoidance);
        Assert.True(state.HasRecoveryStartTime);
        return state;
    }
}

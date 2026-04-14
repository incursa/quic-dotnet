namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P8-0003">A sender MAY implement alternative mechanisms to update its congestion window after periods of underutilization, such as those proposed for TCP in RFC 7661.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P8-0003")]
public sealed class REQ_QUIC_RFC9002_S7P8_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
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

    [Theory]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [InlineData(1_200UL, 6_240UL)]
    [InlineData(3_000UL, 6_600UL)]
    [InlineData(6_000UL, 7_200UL)]
    public void TryRegisterAcknowledgedPacket_GrowsTheCongestionWindowByOneDatagramPerCongestionWindowAcknowledged(
        ulong acknowledgedBytes,
        ulong expectedCongestionWindowBytes)
    {
        QuicCongestionControlState state = CreateCongestionAvoidanceState();
        state.RegisterPacketSent(acknowledgedBytes);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: acknowledgedBytes,
            sentAtMicros: 2_000,
            packetInFlight: true,
            pacingLimited: true));

        Assert.Equal(expectedCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.True(state.IsInCongestionAvoidance);
    }

    private static QuicCongestionControlState CreateCongestionAvoidanceState()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
        Assert.True(state.IsInCongestionAvoidance);
        return state;
    }
}

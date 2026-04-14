namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0039">Upon detecting losses, a sender MUST take appropriate congestion control action.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0039")]
public sealed class REQ_QUIC_RFC9000_S13P3_0039
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_EntersRecoveryAndReducesTheCongestionWindowOnEligibleLossSignals()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterLoss_DoesNotChangeTheCongestionWindowForIneligibleLossSignals()
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

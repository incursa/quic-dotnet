namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P2-0002">A sender that is already in a recovery period MUST NOT reenter it.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P3P2-0002")]
public sealed class REQ_QUIC_RFC9002_S7P3P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterLoss_DoesNotReenterRecoveryForOlderLossSignals()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_500,
            packetInFlight: true));
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryProcessEcn_DoesNotReenterRecoveryForOlderAckedPackets()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 1_500,
            pathValidated: true));
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }
}

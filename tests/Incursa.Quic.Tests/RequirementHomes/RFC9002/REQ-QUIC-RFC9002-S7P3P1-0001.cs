namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P1-0001">A sender MUST enter a recovery period when it detects packet loss or when the ECN-CE count reported by its peer increases.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P3P1-0001")]
public sealed class REQ_QUIC_RFC9002_S7P3P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterLoss_EntersRecoveryOnPacketLoss()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_500,
            packetInFlight: true));

        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(1_500UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryProcessEcn_EntersRecoveryWhenTheEcnCeCountIncreases()
    {
        QuicCongestionControlState state = new();

        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 2_000,
            pathValidated: true));

        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals()
    {
        QuicCongestionControlState ackOnlyLossState = new();
        Assert.True(ackOnlyLossState.TryRegisterLoss(
            sentBytes: 0,
            sentAtMicros: 500,
            packetInFlight: false,
            allowAckOnlyLossSignal: true));
        Assert.Equal(500UL, ackOnlyLossState.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, ackOnlyLossState.CongestionWindowBytes);

        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));
        Assert.Equal(13_200UL, state.CongestionWindowBytes);

        Assert.False(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 100,
            packetInFlight: true,
            packetCanBeDecrypted: false,
            keysAvailable: false,
            sentAfterEarliestAcknowledgedPacket: false));
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true,
            packetCanBeDecrypted: true,
            keysAvailable: true,
            sentAfterEarliestAcknowledgedPacket: true));
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_600UL, state.CongestionWindowBytes);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 1_500,
            pathValidated: false));
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);

        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 2,
            largestAcknowledgedPacketSentAtMicros: 3_000,
            pathValidated: true));
        Assert.Equal(3_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(3_300UL, state.CongestionWindowBytes);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_500,
            packetInFlight: true));
        Assert.Equal(3_300UL, state.CongestionWindowBytes);

        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 4_000,
            packetInFlight: true));
        Assert.Equal(3_736UL, state.CongestionWindowBytes);
    }
}

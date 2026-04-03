namespace Incursa.Quic.Tests;

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
}

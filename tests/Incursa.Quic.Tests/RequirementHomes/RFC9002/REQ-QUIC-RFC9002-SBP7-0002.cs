namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP7-0002")]
public sealed class REQ_QUIC_RFC9002_SBP7_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessEcn_UsesTheLargestAcknowledgedPacketSendTimeWhenItStartsRecovery()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 4_200,
            pathValidated: true));

        Assert.Equal(4_200UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessEcn_DoesNotStartRecoveryWhenTheCeCountDoesNotIncrease()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 0,
            largestAcknowledgedPacketSentAtMicros: 4_200,
            pathValidated: true));

        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessEcn_CanUseTheZeroSendTimeBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 0,
            pathValidated: true));

        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(0UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }
}

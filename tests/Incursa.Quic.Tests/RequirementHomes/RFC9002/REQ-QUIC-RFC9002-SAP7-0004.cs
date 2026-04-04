namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP7-0004")]
public sealed class REQ_QUIC_RFC9002_SAP7_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLossTryRegisterAcknowledgedPacketAndTryProcessEcn_ApplyAckProcessingStateChanges()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 3_000,
            packetInFlight: true));

        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.Equal(6_240UL, state.CongestionWindowBytes);
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);

        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 3_500,
            pathValidated: true));

        Assert.Equal(3_500UL, state.RecoveryStartTimeMicros);
        Assert.Equal(3_120UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessEcn_DoesNotChangeRecoveryWhenThePathIsNotValidated()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 1_500,
            pathValidated: false));

        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessEcn_UsesTheZeroSendTimeBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 0,
            pathValidated: true));

        Assert.Equal(0UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }
}

namespace Incursa.Quic.Tests;

public sealed class QuicCongestionControlStateTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7-0005")]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0005")]
    [Trait("Category", "Positive")]
    public void Constructor_SeedsTheControllerWithTheInitialWindowAndKeepsInstancesIndependent()
    {
        QuicCongestionControlState firstPath = new();
        QuicCongestionControlState secondPath = new(1_500);

        Assert.Equal((ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, firstPath.MaxDatagramSizeBytes);
        Assert.Equal(12_000UL, firstPath.CongestionWindowBytes);
        Assert.Equal(2_400UL, firstPath.MinimumCongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, firstPath.SlowStartThresholdBytes);
        Assert.Equal(0UL, firstPath.BytesInFlightBytes);
        Assert.True(firstPath.IsInSlowStart);

        Assert.Equal(1_500UL, secondPath.MaxDatagramSizeBytes);
        Assert.Equal(14_720UL, secondPath.CongestionWindowBytes);
        Assert.Equal(3_000UL, secondPath.MinimumCongestionWindowBytes);

        firstPath.RegisterPacketSent(1_200);
        Assert.Equal(1_200UL, firstPath.BytesInFlightBytes);
        Assert.Equal(0UL, secondPath.BytesInFlightBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0004")]
    [Trait("Category", "Positive")]
    public void ComputeInitialWindowAndResetToInitialWindow_FollowTheDatagramSize()
    {
        Assert.Equal(12_000UL, QuicCongestionControlState.ComputeInitialCongestionWindowBytes(1_200));
        Assert.Equal(14_720UL, QuicCongestionControlState.ComputeInitialCongestionWindowBytes(1_500));
        Assert.Equal(2_400UL, QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(1_200));

        QuicCongestionControlState state = new(1_200);
        state.RegisterPacketSent(1_200);
        state.UpdateMaxDatagramSize(1_500, resetToInitialWindow: true);

        Assert.Equal(1_500UL, state.MaxDatagramSizeBytes);
        Assert.Equal(14_720UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7-0006")]
    [Requirement("REQ-QUIC-RFC9002-S7P5-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P5-0002")]
    [Trait("Category", "Positive")]
    public void CanSendAndRegisterPacketSent_TreatAckOnlyPacketsAsFreeButCountProbesAsFlight()
    {
        QuicCongestionControlState state = new();

        Assert.True(state.CanSend(1_200, isAckOnlyPacket: true));
        Assert.True(state.CanSend(1_200, isProbePacket: true));

        state.RegisterPacketSent(state.CongestionWindowBytes);
        Assert.False(state.CanSend(1, isAckOnlyPacket: false, isProbePacket: false));
        Assert.True(state.CanSend(1, isProbePacket: true));

        state.RegisterPacketSent(1_200, isProbePacket: true);
        Assert.Equal(state.CongestionWindowBytes + 1_200UL, state.BytesInFlightBytes);

        state.RegisterPacketSent(1_200, isAckOnlyPacket: true);
        Assert.Equal(state.CongestionWindowBytes + 1_200UL, state.BytesInFlightBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0005")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0006")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0007")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P3-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P3-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P4-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P4-0002")]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0005")]
    [Requirement("REQ-QUIC-RFC9002-S7P8-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P8-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P8-0003")]
    [Trait("Category", "Positive")]
    public void TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers()
    {
        Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
            congestionWindowBytes: 10_000,
            smoothedRttMicros: 1_000,
            packetSizeBytes: 1_250,
            ackOnlyPacket: false,
            out ulong pacingIntervalMicros));
        Assert.Equal(100UL, pacingIntervalMicros);

        Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
            congestionWindowBytes: 10_000,
            smoothedRttMicros: 1_000,
            packetSizeBytes: 1_250,
            ackOnlyPacket: true,
            out ulong ackOnlyIntervalMicros));
        Assert.Equal(0UL, ackOnlyIntervalMicros);

        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: false,
            out ulong cappedBurstBytes));
        Assert.Equal(12_000UL, cappedBurstBytes);

        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: true,
            out ulong expandedBurstBytes,
            largerBurstLimitBytes: 24_000));
        Assert.Equal(24_000UL, expandedBurstBytes);

        QuicCongestionControlState state = new();
        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: false));
        Assert.Equal(12_000UL, state.CongestionWindowBytes);

        state = new QuicCongestionControlState();
        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: true));
        Assert.Equal(13_200UL, state.CongestionWindowBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P6-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0005")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0006")]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
    public void TryDetectPersistentCongestion_RequiresAckElicitingLossesAcrossTheWindow()
    {
        Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out ulong durationMicros));
        Assert.Equal(6_000UL, durationMicros);

        Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros: 1_000,
            rttVarMicros: 400,
            maxAckDelayMicros: 500,
            out ulong adjustedDurationMicros));
        Assert.Equal(9_300UL, adjustedDurationMicros);

        Assert.Equal(9_000UL, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
            12_000,
            reductionNumerator: 3,
            reductionDenominator: 4,
            minimumCongestionWindowBytes: 2_400));

        Assert.Equal(2_400UL, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
            1_000,
            reductionNumerator: 3,
            reductionDenominator: 4,
            minimumCongestionWindowBytes: 2_400));

        QuicCongestionControlState failingState = new();
        QuicPersistentCongestionPacket[] failingPackets =
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.Handshake, 5_000, 1_200, true, true, acknowledged: true, lost: false),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];

        Assert.True(failingState.TryDetectPersistentCongestion(
            failingPackets,
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool failingPersistentCongestionDetected));
        Assert.False(failingPersistentCongestionDetected);
        Assert.Equal(6_000UL, failingState.CongestionWindowBytes);
        Assert.True(failingState.HasRecoveryStartTime);

        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        QuicPersistentCongestionPacket[] packets =
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];

        Assert.True(state.TryDetectPersistentCongestion(
            packets,
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
    }
}

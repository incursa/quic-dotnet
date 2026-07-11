// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0156")]
public sealed class REQ_QUIC_CRT_0156
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DefaultSendRuntimeConstructsTheNewRenoControllerByDefault()
    {
        QuicConnectionSendRuntime runtime = new();
        using QuicConnectionRuntime connectionRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicSenderRecoveryRuntime recoveryRuntime = new();

        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            runtime.FlowController.CongestionControlState.CongestionControlAlgorithm);
        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            new QuicSenderFlowController().CongestionControlState.CongestionControlAlgorithm);
        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            connectionRuntime.SendRuntime.FlowController.CongestionControlState.CongestionControlAlgorithm);
        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            recoveryRuntime.SenderFlowController.CongestionControlState.CongestionControlAlgorithm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExplicitCubicSelectionIsChosenAtConstructionTimeAndRemainsImmutable()
    {
        QuicConnectionSendRuntime runtime = new(congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);
        using QuicConnectionRuntime connectionRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);
        QuicSenderRecoveryRuntime recoveryRuntime = new(
            congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);

        Assert.Equal(
            QuicCongestionControlAlgorithm.Cubic,
            runtime.FlowController.CongestionControlState.CongestionControlAlgorithm);
        Assert.Equal(
            QuicCongestionControlAlgorithm.Cubic,
            connectionRuntime.SendRuntime.FlowController.CongestionControlState.CongestionControlAlgorithm);
        Assert.Equal(
            QuicCongestionControlAlgorithm.Cubic,
            recoveryRuntime.SenderFlowController.CongestionControlState.CongestionControlAlgorithm);

        runtime.FlowController.CongestionControlState.UpdateMaxDatagramSize(1_400, resetToInitialWindow: true);

        Assert.Equal(
            QuicCongestionControlAlgorithm.Cubic,
            runtime.FlowController.CongestionControlState.CongestionControlAlgorithm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-CRT-0157")]
    public void DefaultNewRenoKeepsTheExistingRFC9002GrowthAndLossFloor()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(12_000);
        state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: true,
            ackReceivedAtMicros: 2_000);

        Assert.Equal(13_200UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);

        state.RegisterPacketSent(12_000);
        state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 3_000,
            packetInFlight: true);

        Assert.Equal(6_600UL, state.CongestionWindowBytes);
        Assert.Equal(6_600UL, state.SlowStartThresholdBytes);
        Assert.True(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-CRT-0158")]
    public void CubicControllerGrowsDeterministicallyAfterRecoveryEpochStarts()
    {
        QuicCongestionControlState state = new(congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);

        state.RegisterPacketSent(12_000);
        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));
        Assert.Equal(8_400UL, state.CongestionWindowBytes);
        Assert.Equal(8_400UL, state.SlowStartThresholdBytes);
        Assert.Equal(1_000UL, state.RecoveryStartTimeMicros);

        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_100_000,
            packetInFlight: true,
            pacingLimited: true,
            ackReceivedAtMicros: 1_200_000));

        Assert.Equal(16_800UL, state.CongestionWindowBytes);
        Assert.Null(state.RecoveryStartTimeMicros);

        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 3_400_000,
            packetInFlight: true,
            pacingLimited: true,
            ackReceivedAtMicros: 4_500_000));

        Assert.Equal(20_400UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-CRT-0159")]
    public void CubicControllerResetRestoresInitialPathStateAndPreservesItsSelection()
    {
        QuicCongestionControlState state = new(congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);

        state.RegisterPacketSent(12_000);
        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));
        Assert.Equal(8_400UL, state.CongestionWindowBytes);
        Assert.True(state.HasRecoveryStartTime);

        state.Reset();

        Assert.Equal(QuicCongestionControlAlgorithm.Cubic, state.CongestionControlAlgorithm);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.Equal(1_200UL, state.MaxDatagramSizeBytes);
        Assert.Equal(2_400UL, state.MinimumCongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(0UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-CRT-0160")]
    public void CubicControllerStateStaysLocalToEachConnectionRuntime()
    {
        QuicConnectionSendRuntime cubicRuntime = new(congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);
        QuicConnectionSendRuntime newRenoRuntime = new();

        cubicRuntime.FlowController.CongestionControlState.RegisterPacketSent(12_000);
        Assert.True(cubicRuntime.FlowController.CongestionControlState.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.Equal(8_400UL, cubicRuntime.FlowController.CongestionControlState.CongestionWindowBytes);
        Assert.Equal(12_000UL, newRenoRuntime.FlowController.CongestionControlState.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, newRenoRuntime.FlowController.CongestionControlState.SlowStartThresholdBytes);

        newRenoRuntime.FlowController.CongestionControlState.RegisterPacketSent(12_000);
        Assert.True(newRenoRuntime.FlowController.CongestionControlState.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.Equal(8_400UL, cubicRuntime.FlowController.CongestionControlState.CongestionWindowBytes);
        Assert.Equal(6_000UL, newRenoRuntime.FlowController.CongestionControlState.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-CRT-0161")]
    public void CubicControllerNormalizesDatagramSizeAndSuppressesLimitedGrowth()
    {
        QuicCongestionControlState state = new(
            maxDatagramSizeBytes: 1_000,
            congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);

        Assert.Equal(1_000UL, state.MaxDatagramSizeBytes);
        Assert.Equal(2_400UL, state.MinimumCongestionWindowBytes);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);

        foreach ((bool applicationLimited, bool flowControlLimited) in new[]
        {
            (true, false),
            (false, true),
        })
        {
            QuicCongestionControlState limitedState = new(
                maxDatagramSizeBytes: 1_000,
                congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);

            limitedState.RegisterPacketSent(12_000);

            Assert.True(limitedState.TryRegisterAcknowledgedPacket(
                sentBytes: 1_200,
                sentAtMicros: 1_000,
                packetInFlight: true,
                applicationLimited: applicationLimited,
                flowControlLimited: flowControlLimited,
                pacingLimited: true,
                ackReceivedAtMicros: 2_000));

            Assert.Equal(12_000UL, limitedState.CongestionWindowBytes);
            Assert.Equal(10_800UL, limitedState.BytesInFlightBytes);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-CRT-0158")]
    public void ProductionRuntimeCubicLossUsesTheApplicationLimitedFlightSize()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);

        for (ulong packetNumber = 1; packetNumber <= 4; packetNumber++)
        {
            runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                PayloadBytes: 1_200,
                SentAtMicros: packetNumber * 100));
        }

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4));

        QuicCongestionControlState state = runtime.SendRuntime.FlowController.CongestionControlState;
        Assert.Equal(3_360UL, state.CongestionWindowBytes);
        Assert.Equal(3_360UL, state.SlowStartThresholdBytes);
        Assert.Equal(3_600UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-CRT-0158")]
    public void CubicEcnUsesFlightSizeAndContinuesReducingToOneDatagram()
    {
        QuicCongestionControlState state = new(congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 1_000,
            pathValidated: true));
        Assert.Equal(8_400UL, state.CongestionWindowBytes);

        Assert.True(state.TryDiscardPacket(sentBytes: 6_000, packetInFlight: true));
        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 2,
            largestAcknowledgedPacketSentAtMicros: 2_000,
            pathValidated: true));
        Assert.Equal(4_200UL, state.CongestionWindowBytes);

        Assert.True(state.TryDiscardPacket(sentBytes: 3_600, packetInFlight: true));
        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 3,
            largestAcknowledgedPacketSentAtMicros: 3_000,
            pathValidated: true));
        Assert.Equal(1_680UL, state.CongestionWindowBytes);
        Assert.Equal(2_400UL, state.SlowStartThresholdBytes);

        Assert.True(state.TryDiscardPacket(sentBytes: 1_200, packetInFlight: true));
        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 4,
            largestAcknowledgedPacketSentAtMicros: 4_000,
            pathValidated: true));
        Assert.Equal(1_200UL, state.CongestionWindowBytes);
        Assert.Equal(2_400UL, state.SlowStartThresholdBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-CRT-0158")]
    public void RepeatedCubicLossStartsANewEpochAndAppliesFastConvergence()
    {
        QuicCongestionControlState state = new(congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));
        Assert.Equal(12_000UL, state.CubicWindowMaxBytes);
        Assert.Equal(1_000UL, state.CubicEpochStartMicros);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 7_200,
            sentAtMicros: 500,
            packetInFlight: true));
        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));
        Assert.Equal(3_360UL, state.CongestionWindowBytes);
        Assert.Equal(7_140UL, state.CubicWindowMaxBytes);
        Assert.Equal(2_000UL, state.CubicEpochStartMicros);
    }
}

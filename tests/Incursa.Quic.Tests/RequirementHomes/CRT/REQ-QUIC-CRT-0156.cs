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

        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            runtime.FlowController.CongestionControlState.CongestionControlAlgorithm);
        Assert.Equal(
            QuicCongestionControlAlgorithm.NewReno,
            new QuicSenderFlowController().CongestionControlState.CongestionControlAlgorithm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExplicitCubicSelectionIsChosenAtConstructionTimeAndRemainsImmutable()
    {
        QuicConnectionSendRuntime runtime = new(congestionControlAlgorithm: QuicCongestionControlAlgorithm.Cubic);

        Assert.Equal(
            QuicCongestionControlAlgorithm.Cubic,
            runtime.FlowController.CongestionControlState.CongestionControlAlgorithm);

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
}

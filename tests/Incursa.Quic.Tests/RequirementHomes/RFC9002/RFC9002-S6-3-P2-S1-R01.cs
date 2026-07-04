// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-3-P2-S1-R01">Clients that receive a Retry packet MUST reset congestion control and loss recovery state, including any pending timers.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-3-P2-S1-R01")]
public sealed class RFC9002_S6_3_P2_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetProbeTimeoutBackoffCount_ResetsTheBackoffWhenRetryDiscardsKeys()
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 3,
            initialOrHandshakeKeysDiscarded: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRetryReceivedResetsCongestionControlStateAndPendingTimers()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicCongestionControlState congestionControlState = runtime.SendRuntime.FlowController.CongestionControlState;
        ulong initialCongestionWindowBytes = congestionControlState.CongestionWindowBytes;

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 99,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial)));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.Initial,
            packetNumber: 99));
        Assert.True(congestionControlState.CongestionWindowBytes < initialCongestionWindowBytes);
        Assert.True(congestionControlState.RecoveryStartTimeMicros.HasValue);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(runtime.SendRuntime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 200,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false));
        Assert.Equal(1, runtime.SendRuntime.ProbeTimeoutCount);
        Assert.NotNull(runtime.SendRuntime.LossDetectionDeadlineMicros);

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        Assert.True(retryResult.StateChanged);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Keys, key =>
            key.PacketNumberSpace == QuicPacketNumberSpace.Initial
            && key.PacketNumber == 99);
        Assert.Equal(initialCongestionWindowBytes, congestionControlState.CongestionWindowBytes);
        // Retry immediately replays the bootstrap Initial packets, so the post-reset
        // bytes-in-flight count can reflect the fresh ClientHello rather than the discarded packet.
        Assert.False(congestionControlState.RecoveryStartTimeMicros.HasValue);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.Equal(0, runtime.SendRuntime.ProbeTimeoutCount);
        Assert.Null(runtime.SendRuntime.LossDetectionDeadlineMicros);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery));
    }
}

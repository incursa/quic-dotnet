// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-2-2-P3-S2-R01">When Initial or Handshake keys are discarded, the PTO and loss detection timers MUST be reset.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-2-2-P3-S2-R01")]
public sealed class REQ_QUIC_RFC9002_S6P2P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_ResetsPtoStateWhenInitialKeysAreDiscarded()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: new byte[] { 0x01 }));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x02 }));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 300,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false));
        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.NotNull(runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiscardingInitialKeysResetsTheRecoveryControllerTimerState()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.Initial,
            packetNumber: 1,
            sentAtMicros: 100,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.Initial);
        controller.RecordProbeTimeoutExpired();

        Assert.True(controller.TrySelectLossDetectionTimer(
            nowMicros: 200,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: false,
            handshakeKeysAvailable: true,
            out ulong selectedRecoveryTimerMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, selectedPacketNumberSpace);
        Assert.NotEqual(0UL, selectedRecoveryTimerMicros);
        Assert.Equal(1, controller.ProbeTimeoutBackoffCount);

        Assert.True(controller.TryDiscardPacketNumberSpace(
            QuicPacketNumberSpace.Initial,
            resetProbeTimeoutBackoff: true));

        Assert.Equal(0, controller.ProbeTimeoutBackoffCount);
        Assert.False(controller.TrySelectLossDetectionTimer(
            nowMicros: 300,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: false,
            handshakeKeysAvailable: true,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDiscardPacketNumberSpace_ResetsPtoStateWhenHandshakeKeysAreDiscarded()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake),
            PacketBytes: new byte[] { 0x21 }));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x22 }));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Handshake,
            nowMicros: 300,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.NotNull(runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDiscardPacketNumberSpace_LeavesPtoBackoffCountUnchangedWhenApplicationDataIsDiscarded()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x11 }));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 250,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true));

        int probeTimeoutCountBeforeDiscard = runtime.ProbeTimeoutCount;

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData));
        Assert.Equal(probeTimeoutCountBeforeDiscard, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
        Assert.Empty(runtime.SentPackets);
    }
}

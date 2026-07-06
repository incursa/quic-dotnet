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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryDiscardPacketNumberSpace_ResetsTimersForDiscardedInitialAndHandshakeKeys()
    {
        foreach ((QuicPacketNumberSpace discardedSpace, QuicTlsEncryptionLevel protectionLevel, ulong nowMicros, ulong smoothedRttMicros, ulong rttVarMicros) in new[]
        {
            (QuicPacketNumberSpace.Initial, QuicTlsEncryptionLevel.Initial, 10UL, 1_000UL, 250UL),
            (QuicPacketNumberSpace.Initial, QuicTlsEncryptionLevel.Initial, 777UL, 333UL, 44UL),
            (QuicPacketNumberSpace.Handshake, QuicTlsEncryptionLevel.Handshake, 100UL, 2_500UL, 750UL),
            (QuicPacketNumberSpace.Handshake, QuicTlsEncryptionLevel.Handshake, 9_999UL, 1UL, 0UL),
        })
        {
            QuicConnectionSendRuntime runtime = new();
            TrackPacket(runtime, discardedSpace, protectionLevel, packetNumber: 1, packetByte: 0x51);
            TrackPacket(runtime, QuicPacketNumberSpace.ApplicationData, QuicTlsEncryptionLevel.OneRtt, packetNumber: 2, packetByte: 0x52);

            Assert.True(runtime.TryArmProbeTimeout(
                discardedSpace,
                nowMicros,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros: 25_000,
                handshakeConfirmed: false));
            Assert.Equal(1, runtime.ProbeTimeoutCount);
            Assert.NotNull(runtime.LossDetectionDeadlineMicros);

            Assert.True(runtime.TryDiscardPacketNumberSpace(discardedSpace));

            Assert.Equal(0, runtime.ProbeTimeoutCount);
            Assert.Null(runtime.LossDetectionDeadlineMicros);
            Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == discardedSpace);
            Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
        }
    }

    private static void TrackPacket(
        QuicConnectionSendRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        QuicTlsEncryptionLevel protectionLevel,
        ulong packetNumber,
        byte packetByte)
    {
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            PayloadBytes: 1_200,
            SentAtMicros: packetNumber * 100,
            AckEliciting: true,
            CryptoMetadata: packetNumberSpace is QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake
                ? new QuicConnectionCryptoSendMetadata(protectionLevel)
                : null,
            PacketBytes: new byte[] { packetByte },
            PacketProtectionLevel: protectionLevel));
    }
}

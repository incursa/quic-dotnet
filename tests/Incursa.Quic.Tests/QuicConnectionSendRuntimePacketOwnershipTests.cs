// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionSendRuntimePacketOwnershipTests
{
    [Fact]
    public void TrackAndAcknowledgePacket_UsesAuthoritativeLedgerForCongestionState()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(packetNumber: 7, payloadBytes: 1_200));

        Assert.Single(runtime.SentPackets);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
        Assert.Equal(1_200UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);

        using QuicAckFrame ackFrame = QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(7);
        QuicConnectionSentPacket packet = Assert.Single(runtime.SentPackets).Value;
        Assert.True(runtime.FlowController.TryRegisterExternallyRetainedAcknowledgment(packet, ackReceivedAtMicros: 200));
        _ = runtime.FlowController.TryFinalizeExternallyRetainedAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 200,
            largestAcknowledgedPacketSentAtMicros: packet.SentAtMicros);
        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            handshakeConfirmed: true));

        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    public void RegisterLoss_UsesAuthoritativeLedgerForCongestionState()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(packetNumber: 11, payloadBytes: 900));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            handshakeConfirmed: true,
            scheduleRetransmission: false));

        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    public void ProcessDiscontiguousAcknowledgments_UsesAuthoritativeLedgerForEveryAcknowledgedPacket()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(packetNumber: 7, payloadBytes: 700, sentAtMicros: 100));
        runtime.TrackSentPacket(CreatePacket(packetNumber: 8, payloadBytes: 800, sentAtMicros: 200));
        runtime.TrackSentPacket(CreatePacket(packetNumber: 9, payloadBytes: 900, sentAtMicros: 300));
        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 8,
            handshakeConfirmed: true,
            scheduleRetransmission: false));
        Assert.Equal(200UL, runtime.FlowController.CongestionControlState.RecoveryStartTimeMicros);

        using QuicAckFrame ackFrame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 9,
            firstAckRange: 0,
            gap: 0,
            ackRangeLength: 0);
        foreach (ulong packetNumber in new[] { 7UL, 9UL })
        {
            QuicConnectionSentPacketKey key = new(QuicPacketNumberSpace.ApplicationData, packetNumber);
            QuicConnectionSentPacket packet = runtime.SentPackets[key];
            Assert.True(runtime.FlowController.TryRegisterExternallyRetainedAcknowledgment(
                packet,
                ackReceivedAtMicros: 400,
                pacingLimited: true));
            if (packetNumber == 7)
            {
                Assert.Equal(200UL, runtime.FlowController.CongestionControlState.RecoveryStartTimeMicros);
            }

            Assert.True(runtime.TryAcknowledgePacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                handshakeConfirmed: true));
        }

        _ = runtime.FlowController.TryFinalizeExternallyRetainedAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 400,
            largestAcknowledgedPacketSentAtMicros: 300);

        Assert.Empty(runtime.SentPackets);
        Assert.Null(runtime.FlowController.CongestionControlState.RecoveryStartTimeMicros);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
    }

    [Fact]
    public void DiscardKeyPhaseAndProtectionLevel_UseAuthoritativeLedgerForCongestionState()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(packetNumber: 7, payloadBytes: 700, oneRttKeyPhase: 0));
        runtime.TrackSentPacket(CreatePacket(packetNumber: 8, payloadBytes: 800, oneRttKeyPhase: 1));

        Assert.True(runtime.TryDiscardOneRttKeyPhase(0));
        Assert.Single(runtime.SentPackets);
        Assert.Equal(800UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);

        Assert.True(runtime.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.OneRtt));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
    }

    private static QuicConnectionSentPacket CreatePacket(
        ulong packetNumber,
        ulong payloadBytes,
        ulong oneRttKeyPhase = 0,
        ulong sentAtMicros = 100)
        => new(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            payloadBytes,
            SentAtMicros: sentAtMicros,
            AckEliciting: true,
            Retransmittable: true,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            OneRttKeyPhase: oneRttKeyPhase);
}

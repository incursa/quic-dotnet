namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0105")]
public sealed class REQ_QUIC_CRT_0105
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SenderRecoveryRuntimeTracksPacketsAndOwnsPtoSelection()
    {
        QuicSenderRecoveryRuntime runtime = new();

        runtime.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 42,
            sentBytes: 1200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        Assert.Equal(1, runtime.PendingSentPacketCount);
        Assert.True(runtime.HasAckElicitingPacketsInFlight);
        Assert.True(runtime.TryGetSentPacket(QuicPacketNumberSpace.ApplicationData, 42, out QuicSenderPacketRecord packetRecord));
        Assert.Equal(42UL, packetRecord.PacketNumber);
        Assert.Equal(1200UL, packetRecord.SentBytes);
        Assert.Equal(1_000UL, packetRecord.SentAtMicros);
        Assert.True(packetRecord.AckEliciting);

        bool hasTimer = runtime.TrySelectLossDetectionTimer(
            nowMicros: 2_000,
            maxAckDelayMicros: 25,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out ulong selectedRecoveryTimerMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace);

        Assert.True(hasTimer);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
        Assert.True(selectedRecoveryTimerMicros > 2_000);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProbeTimeoutBackoffCanBeAdvancedThroughTheRuntimeOwner()
    {
        QuicSenderRecoveryRuntime runtime = new();

        Assert.Equal(0, runtime.ProbeTimeoutBackoffCount);
        runtime.RecordProbeTimeoutExpired();
        Assert.Equal(1, runtime.ProbeTimeoutBackoffCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiscardingInitialAndHandshakePacketNumberSpacesCleansUpSenderRecoveryState()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1200,
            SentAtMicros: 100,
            AckEliciting: true));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 2,
            PayloadBytes: 1200,
            SentAtMicros: 200,
            AckEliciting: true));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 3,
            PayloadBytes: 1200,
            SentAtMicros: 300,
            AckEliciting: true));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 400,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false));
        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Initial, 1, handshakeConfirmed: false));
        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.ProbeTimeoutCount > 0);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
        Assert.Equal(0, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake));
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Single(runtime.SentPackets);
        Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
    }
}

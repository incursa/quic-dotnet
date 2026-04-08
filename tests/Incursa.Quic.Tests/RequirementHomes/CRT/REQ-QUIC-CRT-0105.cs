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
}

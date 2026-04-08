namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0007")]
public sealed class REQ_QUIC_RFC9001_S4_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetransmissionPlansPreserveTheOriginalCryptoMetadata()
    {
        QuicConnectionSendRuntime runtime = new();
        QuicConnectionCryptoSendMetadata cryptoMetadata = new(QuicTlsEncryptionLevel.Handshake);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 11,
            PayloadBytes: 1_200,
            SentAtMicros: 300,
            AckEliciting: true,
            CryptoMetadata: cryptoMetadata));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            11,
            handshakeConfirmed: false));

        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(QuicPacketNumberSpace.Handshake, retransmission.PacketNumberSpace);
        Assert.Equal(cryptoMetadata, retransmission.CryptoMetadata);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, retransmission.CryptoMetadata!.Value.EncryptionLevel);
        Assert.Empty(runtime.SentPackets);
    }
}

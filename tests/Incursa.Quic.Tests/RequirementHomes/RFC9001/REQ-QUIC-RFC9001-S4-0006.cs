namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0006")]
public sealed class REQ_QUIC_RFC9001_S4_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SenderRuntimePreservesCryptoMetadataWhenTrackingSentPacket()
    {
        QuicConnectionSendRuntime runtime = new();
        QuicConnectionCryptoSendMetadata cryptoMetadata = new(QuicTlsEncryptionLevel.Handshake);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            CryptoMetadata: cryptoMetadata));

        Assert.Single(runtime.SentPackets);

        QuicConnectionSentPacket storedPacket = runtime.SentPackets[
            new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Handshake, 7)];

        Assert.True(storedPacket.CryptoMetadata.HasValue);
        Assert.Equal(cryptoMetadata, storedPacket.CryptoMetadata);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, storedPacket.CryptoMetadata.Value.EncryptionLevel);
        Assert.Equal(QuicPacketNumberSpace.Handshake, storedPacket.PacketNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SenderRuntimeRejectsCryptoMetadataThatDoesNotMatchThePacketNumberSpace()
    {
        QuicConnectionSendRuntime runtime = new();

        Assert.Throws<ArgumentException>(() =>
            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                QuicPacketNumberSpace.Initial,
                PacketNumber: 9,
                PayloadBytes: 1_200,
                SentAtMicros: 200,
                AckEliciting: true,
                CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake))));
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0008")]
public sealed class REQ_QUIC_RFC9001_S4_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SenderRuntimeMapsEncryptionLevelsToPacketNumberSpaces()
    {
        QuicConnectionSendRuntime runtime = new();

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial)));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake)));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 300,
            AckEliciting: true));

        Assert.Equal(QuicTlsEncryptionLevel.Initial, runtime.SentPackets[
            new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Initial, 1)].PacketProtectionLevel);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, runtime.SentPackets[
            new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Handshake, 1)].PacketProtectionLevel);
        Assert.Equal(QuicTlsEncryptionLevel.OneRtt, runtime.SentPackets[
            new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, 1)].PacketProtectionLevel);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0009")]
public sealed class REQ_QUIC_RFC9001_S4_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SenderRuntimeKeepsFrameSemanticsScopedByPacketNumberSpace()
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

        Assert.True(runtime.TryAcknowledgePacket(QuicPacketNumberSpace.Handshake, 1));

        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Contains(runtime.SentPackets.Keys, key =>
            key.PacketNumberSpace == QuicPacketNumberSpace.Initial && key.PacketNumber == 1);
    }
}

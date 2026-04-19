namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6-0001">Loss detection MUST be separate per packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6-0001")]
public sealed class REQ_QUIC_RFC9002_S6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_RemovesOnlyTheDiscardedSpaceFromTheRuntimeLedger()
    {
        QuicConnectionSendRuntime sendRuntime = new();
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: new byte[] { 0x01 }));
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake),
            PacketBytes: new byte[] { 0x02 }));
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 3,
            PayloadBytes: 1_200,
            SentAtMicros: 300,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x03 }));
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 4,
            PayloadBytes: 1_200,
            SentAtMicros: 400,
            AckEliciting: true,
            PacketProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt,
            PacketBytes: new byte[] { 0x04 }));

        Assert.True(sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.DoesNotContain(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && entry.Value.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && entry.Value.PacketProtectionLevel == QuicTlsEncryptionLevel.ZeroRtt);

        Assert.True(sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake));
        Assert.DoesNotContain(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Equal(2, sendRuntime.SentPackets.Count);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && entry.Value.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && entry.Value.PacketProtectionLevel == QuicTlsEncryptionLevel.ZeroRtt);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDiscardPacketNumberSpace_IsNoOpForASpaceThatWasNeverTracked()
    {
        QuicConnectionSendRuntime sendRuntime = new();
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 9,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x09 }));

        Assert.True(sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.Single(sendRuntime.SentPackets);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
    }
}

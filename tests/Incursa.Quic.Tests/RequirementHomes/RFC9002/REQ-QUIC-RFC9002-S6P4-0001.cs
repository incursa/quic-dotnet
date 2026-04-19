namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P4-0001">The sender MUST discard all recovery state associated with packets sent with discarded Initial or Handshake keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P4-0001")]
public sealed class REQ_QUIC_RFC9002_S6P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_RemovesQueuedInitialAndHandshakeRecoveryPlansFromTheRuntimeLedger()
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
            QuicPacketNumberSpace.Initial,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 110,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: new byte[] { 0x02 }));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 3,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake),
            PacketBytes: new byte[] { 0x03 }));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 4,
            PayloadBytes: 1_200,
            SentAtMicros: 210,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake),
            PacketBytes: new byte[] { 0x04 }));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 5,
            PayloadBytes: 1_200,
            SentAtMicros: 300,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x05 }));

        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Initial, 2, handshakeConfirmed: false));
        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Handshake, 4, handshakeConfirmed: true));
        Assert.Equal(3, runtime.SentPackets.Count);
        Assert.Equal(2, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake));
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.True(runtime.PendingRetransmissionCount == 0);
        Assert.Single(runtime.SentPackets);
        Assert.Contains(runtime.SentPackets, entry =>
            entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && entry.Value.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDiscardPacketNumberSpace_LeavesApplicationRecoveryStateAloneWhenNoEarlyKeysWereTracked()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 9,
            PayloadBytes: 1_200,
            SentAtMicros: 900,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x09 }));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 10,
            PayloadBytes: 1_200,
            SentAtMicros: 910,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x0A }));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            10,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.Single(runtime.SentPackets);
        Assert.Contains(runtime.SentPackets, entry =>
            entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
    }
}

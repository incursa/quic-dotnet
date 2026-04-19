namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P4-0002">The sender MUST remove those packets from the count of bytes in flight.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P4-0002")]
public sealed class REQ_QUIC_RFC9002_S6P4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_RemovesInitialAndHandshakePacketsFromBytesInFlight()
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
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake),
            PacketBytes: new byte[] { 0x02 }));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 3,
            PayloadBytes: 1_200,
            SentAtMicros: 300,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x03 }));

        Assert.Equal(3_600UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.Equal(2_400UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake));
        Assert.Equal(1_200UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Single(runtime.SentPackets);
        Assert.Contains(runtime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDiscardPacketNumberSpace_DoesNotChangeBytesInFlightWhenNoEarlyKeysWereTracked()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 700,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x07 }));

        ulong bytesInFlightBeforeDiscard = runtime.FlowController.CongestionControlState.BytesInFlightBytes;

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.Equal(bytesInFlightBeforeDiscard, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Single(runtime.SentPackets);
    }
}

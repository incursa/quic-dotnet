namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P1-0004">An endpoint SHOULD treat receipt of an acknowledgment for a packet it did not send as a connection error of type PROTOCOL_VIOLATION, if it is able to detect the condition.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P1-0004")]
public sealed class REQ_QUIC_RFC9000_S13P1_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcknowledgePacket_RemovesASentPacketFromTracking()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packetBytes = QuicFrameTestData.BuildPingFrame();

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: (ulong)packetBytes.Length,
            SentAtMicros: 1_000,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packetBytes));

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.Empty(runtime.SentPackets);
        Assert.False(runtime.HasAckElicitingPacketsInFlight);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcknowledgePacket_RejectsAnUnsentPacket()
    {
        QuicConnectionSendRuntime runtime = new();

        Assert.False(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.Empty(runtime.SentPackets);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAcknowledgePacket_DoesNotMatchASentPacketAcrossPacketNumberSpaces()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packetBytes = QuicFrameTestData.BuildPingFrame();

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: (ulong)packetBytes.Length,
            SentAtMicros: 1_000,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packetBytes));

        Assert.False(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.Handshake,
            8,
            handshakeConfirmed: true));
        Assert.Single(runtime.SentPackets);
        Assert.True(runtime.SentPackets.ContainsKey(new QuicConnectionSentPacketKey(
            QuicPacketNumberSpace.ApplicationData,
            8)));
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S3-0009")]
public sealed class REQ_QUIC_RFC9002_S3_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrackedReliablePacketsResolveByAcknowledgmentOrLoss()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreateTrackedPacket(packetNumber: 1, packetByte: 0x01));
        runtime.TrackSentPacket(CreateTrackedPacket(packetNumber: 2, packetByte: 0x02));

        Assert.Equal(2, runtime.SentPackets.Count);

        Assert.True(runtime.TryAcknowledgePacket(QuicPacketNumberSpace.ApplicationData, packetNumber: 1));
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumber == 1);

        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 2));
        Assert.Empty(runtime.SentPackets);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(2UL, retransmission.PacketNumber);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    private static QuicConnectionSentPacket CreateTrackedPacket(ulong packetNumber, byte packetByte)
    {
        return new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            PayloadBytes: 1_200,
            SentAtMicros: packetNumber * 1_000,
            AckEliciting: true,
            PacketBytes: new byte[] { packetByte });
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P1-0006")]
public sealed class REQ_QUIC_RFC9000_S13P4P1_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P6-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketNumberSpaces_AreTrackedIndependently()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            1,
            ackEliciting: true,
            receivedAtMicros: 1000,
            ecnCounts: new QuicEcnCounts(1, 0, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            2,
            ackEliciting: true,
            receivedAtMicros: 1010,
            ecnCounts: new QuicEcnCounts(2, 0, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Handshake,
            7,
            ackEliciting: true,
            receivedAtMicros: 1020,
            ecnCounts: new QuicEcnCounts(0, 1, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            4,
            ackEliciting: true,
            receivedAtMicros: 1030,
            ecnCounts: new QuicEcnCounts(0, 0, 2));

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Handshake));
        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Initial, nowMicros: 1100, out QuicAckFrame initialFrame));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Handshake, nowMicros: 1100, out QuicAckFrame handshakeFrame));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1100, out QuicAckFrame applicationFrame));

        Assert.Equal(2UL, initialFrame.LargestAcknowledged);
        Assert.Equal(2UL, initialFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(0UL, initialFrame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(0UL, initialFrame.EcnCounts!.Value.EcnCeCount);
        Assert.Equal(7UL, handshakeFrame.LargestAcknowledged);
        Assert.Equal(0UL, handshakeFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(1UL, handshakeFrame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(0UL, handshakeFrame.EcnCounts!.Value.EcnCeCount);
        Assert.Equal(4UL, applicationFrame.LargestAcknowledged);
        Assert.Equal(0UL, applicationFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(0UL, applicationFrame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(2UL, applicationFrame.EcnCounts!.Value.EcnCeCount);
    }
}

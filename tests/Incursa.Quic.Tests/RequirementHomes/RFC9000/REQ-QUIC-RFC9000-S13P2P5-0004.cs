namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P5-0004">Endpoints SHOULD include buffering delays caused by unavailability of decryption keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P5-0004")]
public sealed class REQ_QUIC_RFC9000_S13P2P5_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_IncludesBufferingDelayFromUnavailableDecryptionKeys()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_300,
            bufferingDelayMicros: 200);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_600,
            out QuicAckFrame frame));

        Assert.Equal(2UL, frame.LargestAcknowledged);
        Assert.Equal(500UL, frame.AckDelay);
        Assert.NotEqual(300UL, frame.AckDelay);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_DoesNotInventBufferingDelayWhenNoneWasRecorded()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_300);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_600,
            out QuicAckFrame frame));

        Assert.Equal(2UL, frame.LargestAcknowledged);
        Assert.Equal(300UL, frame.AckDelay);
        Assert.NotEqual(500UL, frame.AckDelay);
    }
}

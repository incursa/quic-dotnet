namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P5-0001">An endpoint MUST measure the delays intentionally introduced between the time the packet with the largest packet number is received and the time an acknowledgment is sent.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P5-0001")]
public sealed class REQ_QUIC_RFC9000_S13P2P5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_UsesTheLargestPacketReceiptTimeForAckDelay()
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
            ackEliciting: false,
            receivedAtMicros: 1_300);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_600,
            out QuicAckFrame frame));

        Assert.Equal(2UL, frame.LargestAcknowledged);
        Assert.Equal(300UL, frame.AckDelay);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_DoesNotChargeEarlierPacketReceiptTimeWhenTheLargestPacketArrivesLater()
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
            ackEliciting: false,
            receivedAtMicros: 1_300);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            out QuicAckFrame frame));

        Assert.Equal(2UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.AckDelay);
        Assert.NotEqual(300UL, frame.AckDelay);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_ClampsAckDelayToZeroIfTheAckIsSentBeforeTheLargestPacketTimestamp()
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
            ackEliciting: false,
            receivedAtMicros: 1_300);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_299,
            out QuicAckFrame frame));

        Assert.Equal(2UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.AckDelay);
    }
}

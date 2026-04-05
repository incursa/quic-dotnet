namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP7-0001">When an ACK frame is received, the sender MUST update largest_acked_packet[pn_space] to the larger of its current value and ack.largest_acked.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP7-0001")]
public sealed class REQ_QUIC_RFC9002_SAP7_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_TracksTheLargestAcknowledgedPacketPerPacketNumberSpace()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.Initial, 2, ackEliciting: true, receivedAtMicros: 1000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 7, ackEliciting: true, receivedAtMicros: 1100);

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Initial, nowMicros: 1200, out QuicAckFrame initialFrame));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1200, out QuicAckFrame applicationFrame));

        Assert.Equal(2UL, initialFrame.LargestAcknowledged);
        Assert.Equal(7UL, applicationFrame.LargestAcknowledged);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_DoesNotRegressTheLargestAcknowledgedPacketWhenAnOlderPacketArrives()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 7, ackEliciting: true, receivedAtMicros: 1000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 3, ackEliciting: true, receivedAtMicros: 1100);

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1200, out QuicAckFrame frame));
        Assert.Equal(7UL, frame.LargestAcknowledged);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_HandlesPacketNumberZeroAtTheBoundary()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.Handshake, 0, ackEliciting: true, receivedAtMicros: 1000);

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Handshake, nowMicros: 1100, out QuicAckFrame frame));
        Assert.Equal(0UL, frame.LargestAcknowledged);
    }
}

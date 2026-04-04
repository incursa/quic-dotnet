namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP1-0001">A QUIC sender MUST track every ack-eliciting packet until the packet is acknowledged or lost.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP1-0001")]
public sealed class REQ_QUIC_RFC9002_SAP1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordProcessedPacket_KeepsAckElicitingPacketsTrackedUntilTheAckOnlyFrameIsSent()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(tracker.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out QuicAckFrame frame));
        Assert.Equal(7UL, frame.LargestAcknowledged);

        tracker.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_500,
            ackOnlyPacket: true);

        Assert.False(tracker.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_600,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordProcessedPacket_DoesNotTreatNonAckElicitingPacketsAsAckTriggers()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(tracker.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecordProcessedPacket_RequestsImmediateAckForInitialAndHandshakePackets()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Handshake,
            1,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Handshake));
        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
    }
}

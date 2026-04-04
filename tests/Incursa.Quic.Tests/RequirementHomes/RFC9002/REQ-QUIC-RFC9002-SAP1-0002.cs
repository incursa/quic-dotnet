namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP1-0002">Implementations MUST be able to access tracked packet information by packet number and crypto context.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP1-0002")]
public sealed class REQ_QUIC_RFC9002_SAP1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordProcessedPacket_TracksTheSamePacketNumberPerSpaceAndPerPacketNumber()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            42,
            ackEliciting: false,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Handshake,
            42,
            ackEliciting: true,
            receivedAtMicros: 1_100);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            42,
            ackEliciting: false,
            receivedAtMicros: 1_200);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            42,
            ackEliciting: true,
            receivedAtMicros: 1_300);

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Initial, nowMicros: 1_400, out QuicAckFrame initialFrame));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Handshake, nowMicros: 1_400, out QuicAckFrame handshakeFrame));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1_400, out QuicAckFrame applicationFrame));

        Assert.Equal(42UL, initialFrame.LargestAcknowledged);
        Assert.Equal(42UL, handshakeFrame.LargestAcknowledged);
        Assert.Equal(42UL, applicationFrame.LargestAcknowledged);
        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Handshake));
        Assert.True(tracker.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_400,
            maxAckDelayMicros: 1_000));
    }
}

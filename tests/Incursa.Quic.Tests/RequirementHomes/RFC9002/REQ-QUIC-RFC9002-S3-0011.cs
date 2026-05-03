namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0011">Packets MUST be acknowledged unless they are discarded before packet protection is removed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0011")]
public sealed class REQ_QUIC_RFC9002_S3_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryBuildAckFrame_AcknowledgesProcessedNonAckElicitingPackets()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            5,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out QuicAckFrame frame));
        Assert.Equal(5UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
    }
}

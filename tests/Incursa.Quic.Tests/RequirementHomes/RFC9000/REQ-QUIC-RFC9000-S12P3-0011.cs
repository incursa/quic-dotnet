namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0011">A receiver MUST discard a newly unprotected packet unless it is certain that it has not processed another packet with the same packet number from the same packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0011")]
public sealed class REQ_QUIC_RFC9000_S12P3_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordIncomingPacket_MergesDuplicatePacketNumbersIntoASingleAckRange()
    {
        QuicSenderFlowController tracker = new();

        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_200);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            out QuicAckFrame frame));

        Assert.Equal(5UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordIncomingPacket_KeepsMatchingPacketNumbersSeparatedByPacketNumberSpace()
    {
        QuicSenderFlowController tracker = new();

        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.Initial,
            nowMicros: 1_200,
            out QuicAckFrame initialFrame));
        Assert.Equal(7UL, initialFrame.LargestAcknowledged);
        Assert.Equal(0UL, initialFrame.FirstAckRange);
        Assert.Empty(initialFrame.AdditionalRanges);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out QuicAckFrame applicationFrame));
        Assert.Equal(7UL, applicationFrame.LargestAcknowledged);
        Assert.Equal(0UL, applicationFrame.FirstAckRange);
        Assert.Empty(applicationFrame.AdditionalRanges);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecordIncomingPacket_HandlesTheLargestPacketNumberWithoutSplittingTheRange()
    {
        QuicSenderFlowController tracker = new();

        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: ulong.MaxValue,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: ulong.MaxValue,
            ackEliciting: true,
            receivedAtMicros: 1_200);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            out QuicAckFrame frame));

        Assert.Equal(ulong.MaxValue, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }
}

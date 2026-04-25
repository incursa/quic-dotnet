namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0008">Non-ack-eliciting packets are eventually MUST acknowledged when the endpoint sends an ACK frame in response to other events.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0008")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_IncludesPriorNonAckElicitingPacketWhenAckElicitingPacketArrives()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: false,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out QuicAckFrame frame));
        Assert.Equal(5UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_PreservesNonAckElicitingPacketAcrossGapWhenAckElicitingPacketArrives()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: false,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 6,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out QuicAckFrame frame));
        Assert.Equal(6UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        QuicAckRange range = Assert.Single(frame.AdditionalRanges);
        Assert.Equal(4UL, range.SmallestAcknowledged);
        Assert.Equal(4UL, range.LargestAcknowledged);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryBuildAckFrame_RetainsNonAckElicitingPacketsUntilAckElicitingEvent()
    {
        for (ulong nonAckPacketNumber = 1; nonAckPacketNumber <= 24; nonAckPacketNumber++)
        {
            for (ulong gap = 0; gap <= 3; gap++)
            {
                QuicSenderFlowController sender = new(maximumRetainedAckRanges: 8);
                ulong ackElicitingPacketNumber = nonAckPacketNumber + gap + 1;

                sender.RecordIncomingPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    nonAckPacketNumber,
                    ackEliciting: false,
                    receivedAtMicros: 1_000);
                sender.RecordIncomingPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    ackElicitingPacketNumber,
                    ackEliciting: true,
                    receivedAtMicros: 1_100);

                Assert.True(sender.TryBuildAckFrame(
                    QuicPacketNumberSpace.ApplicationData,
                    nowMicros: 1_200,
                    out QuicAckFrame frame));
                Assert.Equal(ackElicitingPacketNumber, frame.LargestAcknowledged);

                if (gap == 0)
                {
                    Assert.Equal(1UL, frame.FirstAckRange);
                    Assert.Empty(frame.AdditionalRanges);
                }
                else
                {
                    Assert.Equal(0UL, frame.FirstAckRange);
                    Assert.Contains(
                        frame.AdditionalRanges,
                        range => range.SmallestAcknowledged == nonAckPacketNumber
                            && range.LargestAcknowledged == nonAckPacketNumber);
                }
            }
        }
    }
}

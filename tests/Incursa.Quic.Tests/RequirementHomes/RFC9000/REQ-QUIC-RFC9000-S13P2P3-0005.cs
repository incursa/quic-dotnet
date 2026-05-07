namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0005">After receiving acknowledgments for an ACK frame, the receiver SHOULD stop tracking those acknowledged ACK Ranges.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P3-0005")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_RetiresTrackedAckRangesWhenTheCarrierPacketIsAcknowledged()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_010);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_020);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 6,
            ackEliciting: true,
            receivedAtMicros: 1_030);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame ackFrame));
        Assert.Equal(6UL, ackFrame.LargestAcknowledged);
        Assert.Equal(1UL, ackFrame.FirstAckRange);
        Assert.Single(ackFrame.AdditionalRanges);

        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            ackFrame,
            sentAtMicros: 2_100,
            ackOnlyPacket: true);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            new QuicAckFrame
            {
                LargestAcknowledged = 11,
                AckDelay = 0,
                FirstAckRange = 0,
                AdditionalRanges = [],
            },
            ackReceivedAtMicros: 3_000,
            pathValidated: true));

        Assert.False(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 3_100,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_PreservesTrackedAckRangesWhenASeparatePacketNumberSpaceAcknowledgesTheCarrierPacket()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_010);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_020);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 6,
            ackEliciting: true,
            receivedAtMicros: 1_030);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame ackFrame));

        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            ackFrame,
            sentAtMicros: 2_100,
            ackOnlyPacket: true);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.Initial,
            packetNumber: 11,
            sentBytes: 1_200,
            sentAtMicros: 2_200,
            ackEliciting: true);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Initial,
            new QuicAckFrame
            {
                LargestAcknowledged = 11,
                AckDelay = 0,
                FirstAckRange = 0,
                AdditionalRanges = [],
            },
            ackReceivedAtMicros: 3_000,
            pathValidated: true));

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 3_100,
            out QuicAckFrame survivingFrame));
        Assert.Equal(ackFrame.LargestAcknowledged, survivingFrame.LargestAcknowledged);
        Assert.Equal(ackFrame.FirstAckRange, survivingFrame.FirstAckRange);
        Assert.Equal(ackFrame.AdditionalRanges.Length, survivingFrame.AdditionalRanges.Length);
        Assert.Equal(ackFrame.AdditionalRanges[0].SmallestAcknowledged, survivingFrame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(ackFrame.AdditionalRanges[0].LargestAcknowledged, survivingFrame.AdditionalRanges[0].LargestAcknowledged);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessAckFrame_LeavesTrackedAckRangesInPlaceWhenAnUnrelatedPacketIsAcknowledged()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_010);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_020);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 6,
            ackEliciting: true,
            receivedAtMicros: 1_030);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame ackFrame));

        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            ackFrame,
            sentAtMicros: 2_100,
            ackOnlyPacket: true);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 12,
            sentBytes: 1_200,
            sentAtMicros: 2_200,
            ackEliciting: true);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            new QuicAckFrame
            {
                LargestAcknowledged = 12,
                AckDelay = 0,
                FirstAckRange = 0,
                AdditionalRanges = [],
            },
            ackReceivedAtMicros: 3_000,
            pathValidated: true));

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 3_100,
            out QuicAckFrame survivingFrame));
        Assert.Equal(ackFrame.LargestAcknowledged, survivingFrame.LargestAcknowledged);
        Assert.Equal(ackFrame.FirstAckRange, survivingFrame.FirstAckRange);
        Assert.Equal(ackFrame.AdditionalRanges.Length, survivingFrame.AdditionalRanges.Length);
        Assert.Equal(ackFrame.AdditionalRanges[0].SmallestAcknowledged, survivingFrame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(ackFrame.AdditionalRanges[0].LargestAcknowledged, survivingFrame.AdditionalRanges[0].LargestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_RetiresTrackedAckRangesFromHugeAcknowledgmentRange()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.Initial,
            nowMicros: 2_000,
            out QuicAckFrame ackFrame));

        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.Initial,
            packetNumber: 11,
            ackFrame,
            sentAtMicros: 2_100,
            ackOnlyPacket: true);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Initial,
            new QuicAckFrame
            {
                LargestAcknowledged = 1UL << 62,
                AckDelay = 0,
                FirstAckRange = 1UL << 62,
                AdditionalRanges = [],
            },
            ackReceivedAtMicros: 3_000,
            pathValidated: false));

        Assert.False(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.Initial,
            nowMicros: 3_100,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessAckFrame_IgnoresHugeAcknowledgmentRangeWhenNoTrackedPacketsMatch()
    {
        QuicSenderFlowController sender = new();

        sender.RecordPacketSent(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        Assert.False(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Handshake,
            new QuicAckFrame
            {
                LargestAcknowledged = 1UL << 62,
                AckDelay = 0,
                FirstAckRange = (1UL << 62) - 10,
                AdditionalRanges = [],
            },
            ackReceivedAtMicros: 2_000,
            pathValidated: false));

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Handshake,
            new QuicAckFrame
            {
                LargestAcknowledged = 1,
                AckDelay = 0,
                FirstAckRange = 0,
                AdditionalRanges = [],
            },
            ackReceivedAtMicros: 3_000,
            pathValidated: true));
    }

}

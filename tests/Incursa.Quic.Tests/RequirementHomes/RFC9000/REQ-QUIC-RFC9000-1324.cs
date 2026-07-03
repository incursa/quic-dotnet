// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S13-2-2-P5-S1-R01">A receiver MAY process multiple available packets before determining whether to send an ACK frame in response.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S13-2-2-P5-S1-R01")]
public sealed class REQ_QUIC_RFC9000_1324
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_IncludesPacketsProcessedBeforeTheAckDecisionIsMade()
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
            receivedAtMicros: 1_010);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            ackEliciting: true,
            receivedAtMicros: 1_020);

        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out QuicAckFrame frame));

        Assert.Equal(3UL, frame.LargestAcknowledged);
        Assert.Equal(2UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_DoesNotTreatMultipleNonAckElicitingPacketsAsAnAckDecision()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: false,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: false,
            receivedAtMicros: 1_010);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            ackEliciting: false,
            receivedAtMicros: 1_020);

        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_GappedAckElicitingPacketTriggersDecisionAfterEarlierPacketsWereProcessed()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 10,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            ackEliciting: false,
            receivedAtMicros: 1_010);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 13,
            ackEliciting: true,
            receivedAtMicros: 1_020);

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_020,
            maxAckDelayMicros: 1_000));

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_020,
            out QuicAckFrame frame));

        Assert.Equal(13UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);

        QuicAckRange additionalRange = Assert.Single(frame.AdditionalRanges);
        Assert.Equal(0UL, additionalRange.Gap);
        Assert.Equal(1UL, additionalRange.AckRangeLength);
        Assert.Equal(10UL, additionalRange.SmallestAcknowledged);
        Assert.Equal(11UL, additionalRange.LargestAcknowledged);
    }
}

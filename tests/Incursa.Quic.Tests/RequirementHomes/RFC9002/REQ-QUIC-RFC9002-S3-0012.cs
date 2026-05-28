// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0012">Packets that contain no ack-eliciting frames MUST be acknowledged only along with ack-eliciting packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0012")]
public sealed class REQ_QUIC_RFC9002_S3_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void RecordProcessedNonAckElicitingPacket_IsAcknowledgedWithALaterAckElicitingPacket()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            1,
            ackEliciting: false,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            2,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_100,
            maxAckDelayMicros: 1_000));
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_100,
            out QuicAckFrame frame));
        Assert.Equal(2UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordProcessedNonAckElicitingPacket_DoesNotRequestAnImmediateAck()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            1,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void RecordProcessedNonAckElicitingPacket_DoesNotRequestAckAtTheDelayBoundaryByItself()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            1,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            maxAckDelayMicros: 1_000));
    }
}

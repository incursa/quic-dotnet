// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S3-0007")]
public sealed class REQ_QUIC_RFC9002_S3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AckGenerationRetainsRangesWhenPacketNumbersHaveIntentionalGaps()
    {
        QuicAckGenerationState tracker = new();
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 3, ackEliciting: true, receivedAtMicros: 1_100);

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out QuicAckFrame frame));

        Assert.Equal(3UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        QuicAckRange range = Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, range.SmallestAcknowledged);
        Assert.Equal(1UL, range.LargestAcknowledged);
    }
}

namespace Incursa.Quic.Tests;

public sealed class QuicAckGenerationStateTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0003")]
    [Requirement("REQ-QUIC-RFC9002-S2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0006")]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_RoundsTripProcessedPacketsAndReportsAckDelay()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: false, receivedAtMicros: 1000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1100);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 4, ackEliciting: true, receivedAtMicros: 1200);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 5, ackEliciting: false, receivedAtMicros: 1300);

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1600, out QuicAckFrame frame));

        Assert.Equal((byte)0x02, frame.FrameType);
        Assert.Equal(5UL, frame.LargestAcknowledged);
        Assert.Equal(300UL, frame.AckDelay);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(0UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(1UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(2UL, frame.AdditionalRanges[0].LargestAcknowledged);
        Assert.Null(frame.EcnCounts);

        Span<byte> encoded = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, encoded, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded[..bytesWritten], out QuicAckFrame parsed, out int bytesConsumed));

        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
        Assert.Equal(frame.AdditionalRanges.Length, parsed.AdditionalRanges.Length);
        Assert.Equal(frame.AdditionalRanges[0].Gap, parsed.AdditionalRanges[0].Gap);
        Assert.Equal(frame.AdditionalRanges[0].AckRangeLength, parsed.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(frame.AdditionalRanges[0].SmallestAcknowledged, parsed.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(frame.AdditionalRanges[0].LargestAcknowledged, parsed.AdditionalRanges[0].LargestAcknowledged);
        Assert.Null(parsed.EcnCounts);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9002-S2-0003")]
    [Trait("Category", "Positive")]
    public void ShouldSendAckImmediately_ForInitialAndHandshakePackets()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.Initial, 1, ackEliciting: true, receivedAtMicros: 1000);
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));

        tracker.MarkAckFrameSent(QuicPacketNumberSpace.Initial, sentAtMicros: 1100, ackOnlyPacket: true);

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.Handshake, 1, ackEliciting: true, receivedAtMicros: 1200);
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Handshake));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0014")]
    [Trait("Category", "Positive")]
    public void ShouldSendAckImmediately_ForOutOfOrderAndCePackets()
    {
        QuicAckGenerationState outOfOrderTracker = new();
        outOfOrderTracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1000);
        outOfOrderTracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 3, ackEliciting: true, receivedAtMicros: 1100);
        Assert.True(outOfOrderTracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));

        QuicAckGenerationState ceTracker = new();
        ceTracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            ackEliciting: true,
            receivedAtMicros: 1000,
            congestionExperienced: true,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(ceTracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0011")]
    [Requirement("REQ-QUIC-RFC9002-S2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S3-0012")]
    [Trait("Category", "Positive")]
    public void ShouldDelayAckUntilSecondAckElicitingPacketOrMaxAckDelay()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: false, receivedAtMicros: 1000);
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1200, maxAckDelayMicros: 1000));

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1300);
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1400, maxAckDelayMicros: 1000));

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 3, ackEliciting: true, receivedAtMicros: 1500);
        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1600, maxAckDelayMicros: 1000));

        tracker.MarkAckFrameSent(QuicPacketNumberSpace.ApplicationData, sentAtMicros: 1650, ackOnlyPacket: false);
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1700, maxAckDelayMicros: 1000));
        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 2700, maxAckDelayMicros: 1000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0006")]
    [Trait("Category", "Positive")]
    public void CanSendOnlyOneAckOnlyPacketPerAckElicitingPacket()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1000);
        Assert.True(tracker.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1500, maxAckDelayMicros: 1000));

        tracker.MarkAckFrameSent(QuicPacketNumberSpace.ApplicationData, sentAtMicros: 1500, ackOnlyPacket: true);
        Assert.False(tracker.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1600, maxAckDelayMicros: 1000));

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1700);
        Assert.True(tracker.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1800, maxAckDelayMicros: 1000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0011")]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_TrimsOldestRangesWhenLimitReached()
    {
        QuicAckGenerationState keepTwoRanges = new(maximumRetainedAckRanges: 2);
        RecordAckedRanges(keepTwoRanges);

        Assert.True(keepTwoRanges.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 2000, out QuicAckFrame frame));
        Assert.Equal(10UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(5UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(6UL, frame.AdditionalRanges[0].LargestAcknowledged);

        QuicAckGenerationState keepOnlyLargestRange = new(maximumRetainedAckRanges: 1);
        RecordAckedRanges(keepOnlyLargestRange);

        Assert.True(keepOnlyLargestRange.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 2000, out QuicAckFrame compactFrame));
        Assert.Equal(10UL, compactFrame.LargestAcknowledged);
        Assert.Equal(1UL, compactFrame.FirstAckRange);
        Assert.Empty(compactFrame.AdditionalRanges);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P6-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    [Trait("Category", "Positive")]
    public void PacketNumberSpaces_AreTrackedIndependently()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            1,
            ackEliciting: true,
            receivedAtMicros: 1000,
            ecnCounts: new QuicEcnCounts(1, 0, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            2,
            ackEliciting: true,
            receivedAtMicros: 1010,
            ecnCounts: new QuicEcnCounts(2, 0, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Handshake,
            7,
            ackEliciting: true,
            receivedAtMicros: 1020,
            ecnCounts: new QuicEcnCounts(0, 1, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            4,
            ackEliciting: true,
            receivedAtMicros: 1030,
            ecnCounts: new QuicEcnCounts(0, 0, 2));

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Handshake));
        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Initial, nowMicros: 1100, out QuicAckFrame initialFrame));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Handshake, nowMicros: 1100, out QuicAckFrame handshakeFrame));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1100, out QuicAckFrame applicationFrame));

        Assert.Equal(2UL, initialFrame.LargestAcknowledged);
        Assert.Equal(2UL, initialFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(0UL, initialFrame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(0UL, initialFrame.EcnCounts!.Value.EcnCeCount);
        Assert.Equal(7UL, handshakeFrame.LargestAcknowledged);
        Assert.Equal(0UL, handshakeFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(1UL, handshakeFrame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(0UL, handshakeFrame.EcnCounts!.Value.EcnCeCount);
        Assert.Equal(4UL, applicationFrame.LargestAcknowledged);
        Assert.Equal(0UL, applicationFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(0UL, applicationFrame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(2UL, applicationFrame.EcnCounts!.Value.EcnCeCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0014")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0005")]
    [Requirement("REQ-QUIC-RFC9002-S3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_UsesEcnCountsAndReportsMeasuredDelayWhenDelayed()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1000,
            congestionExperienced: true,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 4000, out QuicAckFrame frame));

        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.Equal(8UL, frame.LargestAcknowledged);
        Assert.Equal(3000UL, frame.AckDelay);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(11UL, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(12UL, frame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(13UL, frame.EcnCounts!.Value.EcnCeCount);
        Assert.True(frame.AckDelay > 1000UL);
    }

    private static void RecordAckedRanges(QuicAckGenerationState tracker)
    {
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1010);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 5, ackEliciting: true, receivedAtMicros: 1020);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 6, ackEliciting: true, receivedAtMicros: 1030);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 9, ackEliciting: true, receivedAtMicros: 1040);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 10, ackEliciting: true, receivedAtMicros: 1050);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
public sealed class REQ_QUIC_RFC9000_S13P3_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryBuildAckFrame_UsesTheLargestAcknowledgedPacketForAckDelay()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            4,
            ackEliciting: true,
            receivedAtMicros: 1_600);

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 2_100, out QuicAckFrame frame));
        Assert.Equal(4UL, frame.LargestAcknowledged);
        Assert.Equal(500UL, frame.AckDelay);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(1UL, frame.AdditionalRanges[0].LargestAcknowledged);

        Span<byte> encoded = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, encoded, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded[..bytesWritten], out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryBuildAckFrame_RejectsAnEmptyAckSet()
    {
        QuicAckGenerationState tracker = new();

        Assert.False(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 2_100, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_TryBuildAckFrame_UsesTheLargestAcknowledgedPacketAcrossRandomOrders()
    {
        Random random = new(0x5160_2010);
        Span<byte> encoded = stackalloc byte[32];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            QuicAckGenerationState tracker = new();

            ulong smallestPacket = (ulong)random.Next(0, 32);
            ulong largestPacket = smallestPacket + (ulong)random.Next(2, 32);
            ulong smallestReceivedAtMicros = (ulong)random.Next(0, 1_000);
            ulong largestReceivedAtMicros = (ulong)random.Next(1_000, 2_000);

            tracker.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                smallestPacket,
                ackEliciting: true,
                receivedAtMicros: smallestReceivedAtMicros + (ulong)random.Next(1, 500));
            tracker.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                largestPacket,
                ackEliciting: true,
                receivedAtMicros: largestReceivedAtMicros);

            ulong nowMicros = largestReceivedAtMicros + (ulong)random.Next(0, 500);

            Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros, out QuicAckFrame frame));
            Assert.Equal(largestPacket, frame.LargestAcknowledged);
            Assert.Equal(nowMicros - largestReceivedAtMicros, frame.AckDelay);

            Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, encoded, out int bytesWritten));
            Assert.True(QuicFrameCodec.TryParseAckFrame(encoded[..bytesWritten], out QuicAckFrame parsed, out int bytesConsumed));
            Assert.Equal(bytesWritten, bytesConsumed);
            Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
            Assert.Equal(frame.AckDelay, parsed.AckDelay);
        }
    }
}

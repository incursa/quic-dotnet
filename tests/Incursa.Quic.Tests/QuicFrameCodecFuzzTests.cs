namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecFuzzTests
{
    [Fact]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P1-0001")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P1-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P1-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P1-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P2-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P2-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0001")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0009")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0010")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0011")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0012")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0013")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0014")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0015")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0016")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0017")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0018")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0019")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3-0020")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0001")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0008")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0009")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P1-0010")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P2-0001")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P2-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P2-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P2-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P2-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P2-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P3P2-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P4-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P4-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P4-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P4-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P4-0008")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P4-0009")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P4-0010")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P4-0011")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P5-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P5-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P5-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P5-0008")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P5-0009")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P5-0010")]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FrameCodec_RoundTripsRepresentativeFrameShapesAndRejectsTruncation()
    {
        Random random = new(0x5150_2030);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            switch (random.Next(6))
            {
                case 0:
                    RoundTripPaddingFrame();
                    break;
                case 1:
                    RoundTripPingFrame();
                    break;
                case 2:
                    RoundTripAckFrame(random, includeEcnCounts: false);
                    break;
                case 3:
                    RoundTripAckFrame(random, includeEcnCounts: true);
                    break;
                case 4:
                    RoundTripResetStreamFrame(random);
                    break;
                default:
                    RoundTripStopSendingFrame(random);
                    break;
            }
        }
    }

    private static void RoundTripPaddingFrame()
    {
        byte[] packet = QuicFrameTestData.BuildPaddingFrame();

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packet, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([], out _));
    }

    private static void RoundTripPingFrame()
    {
        byte[] packet = QuicFrameTestData.BuildPingFrame();

        Assert.True(QuicFrameCodec.TryParsePingFrame(packet, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParsePingFrame([], out _));
    }

    private static void RoundTripAckFrame(Random random, bool includeEcnCounts)
    {
        QuicAckFrame frame = BuildRandomAckFrame(random, includeEcnCounts);
        byte[] packet = QuicFrameTestData.BuildAckFrame(frame);

        Assert.True(QuicFrameCodec.TryParseAckFrame(packet, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
        Assert.Equal(frame.AdditionalRanges.Length, parsed.AdditionalRanges.Length);

        for (int index = 0; index < frame.AdditionalRanges.Length; index++)
        {
            Assert.Equal(frame.AdditionalRanges[index].Gap, parsed.AdditionalRanges[index].Gap);
            Assert.Equal(frame.AdditionalRanges[index].AckRangeLength, parsed.AdditionalRanges[index].AckRangeLength);
            Assert.Equal(frame.AdditionalRanges[index].SmallestAcknowledged, parsed.AdditionalRanges[index].SmallestAcknowledged);
            Assert.Equal(frame.AdditionalRanges[index].LargestAcknowledged, parsed.AdditionalRanges[index].LargestAcknowledged);
        }

        Assert.Equal(frame.EcnCounts, parsed.EcnCounts);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseAckFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static QuicAckFrame BuildRandomAckFrame(Random random, bool includeEcnCounts)
    {
        ulong largestAcknowledged = (ulong)random.Next(1, 512);
        ulong firstAckRange = (ulong)random.Next(0, (int)Math.Min(largestAcknowledged, 8));
        ulong previousSmallestAcknowledged = largestAcknowledged - firstAckRange;
        int additionalRangeCount = previousSmallestAcknowledged > 1 ? random.Next(0, 4) : 0;

        List<QuicAckRange> additionalRanges = [];
        for (int index = 0; index < additionalRangeCount && previousSmallestAcknowledged > 1; index++)
        {
            ulong gap = (ulong)random.Next(0, (int)Math.Min(previousSmallestAcknowledged - 1, 4));
            ulong nextLargest = previousSmallestAcknowledged - gap - 2;
            ulong ackRangeLength = (ulong)random.Next(0, (int)Math.Min(nextLargest + 1, 4));
            QuicAckRange range = QuicFrameTestData.BuildAckRange(previousSmallestAcknowledged, gap, ackRangeLength);
            additionalRanges.Add(range);
            previousSmallestAcknowledged = range.SmallestAcknowledged;
        }

        QuicAckFrame frame = new()
        {
            FrameType = includeEcnCounts ? (byte)0x03 : (byte)0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = (ulong)random.Next(0, 256),
            FirstAckRange = firstAckRange,
            AdditionalRanges = additionalRanges.ToArray(),
        };

        if (includeEcnCounts)
        {
            frame.EcnCounts = new QuicEcnCounts(
                (ulong)random.Next(0, 32),
                (ulong)random.Next(0, 32),
                (ulong)random.Next(0, 32));
        }

        return frame;
    }

    private static void RoundTripResetStreamFrame(Random random)
    {
        QuicResetStreamFrame frame = new(
            (ulong)random.Next(0, 4096),
            (ulong)random.Next(0, 256),
            (ulong)random.Next(0, 4096));

        byte[] packet = QuicFrameTestData.BuildResetStreamFrame(frame);
        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(packet, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static void RoundTripStopSendingFrame(Random random)
    {
        QuicStopSendingFrame frame = new(
            (ulong)random.Next(0, 4096),
            (ulong)random.Next(0, 256));

        byte[] packet = QuicFrameTestData.BuildStopSendingFrame(frame);
        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(packet, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseStopSendingFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }
}

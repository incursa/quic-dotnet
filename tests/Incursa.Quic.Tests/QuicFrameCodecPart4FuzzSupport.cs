namespace Incursa.Quic.Tests;

internal static class QuicFrameCodecPart4FuzzSupport
{
    public static void FuzzDataBlockedFrame()
    {
        Random random = new(0x5160_2040);
        Span<byte> destination = stackalloc byte[16];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            QuicDataBlockedFrame frame = new((ulong)random.Next(0, 1 << 20));
            byte[] packet = QuicFrameTestData.BuildDataBlockedFrame(frame);

            Assert.True(QuicFrameCodec.TryParseDataBlockedFrame(packet, out QuicDataBlockedFrame parsed, out int bytesConsumed));
            Assert.Equal(frame.MaximumData, parsed.MaximumData);
            Assert.Equal(packet.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatDataBlockedFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParseDataBlockedFrame(packet[..^1], out _, out _));
        }
    }

    public static void FuzzStreamDataBlockedFrame()
    {
        Random random = new(0x5160_2041);
        Span<byte> destination = stackalloc byte[32];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            QuicStreamDataBlockedFrame frame = new(
                (ulong)random.Next(0, 1 << 16),
                (ulong)random.Next(0, 1 << 20));
            byte[] packet = QuicFrameTestData.BuildStreamDataBlockedFrame(frame);

            Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(packet, out QuicStreamDataBlockedFrame parsed, out int bytesConsumed));
            Assert.Equal(frame.StreamId, parsed.StreamId);
            Assert.Equal(frame.MaximumStreamData, parsed.MaximumStreamData);
            Assert.Equal(packet.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatStreamDataBlockedFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParseStreamDataBlockedFrame(packet[..^1], out _, out _));
        }
    }

    public static void FuzzStreamsBlockedFrame()
    {
        Random random = new(0x5160_2042);
        Span<byte> destination = stackalloc byte[16];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            bool isBidirectional = random.Next(0, 2) == 0;
            ulong maximumStreams = random.Next(0, 16) == 0 ? 1UL << 60 : (ulong)random.Next(0, 1 << 20);
            QuicStreamsBlockedFrame frame = new(isBidirectional, maximumStreams);
            byte[] packet = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

            Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(packet, out QuicStreamsBlockedFrame parsed, out int bytesConsumed));
            Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
            Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
            Assert.Equal(packet.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParseStreamsBlockedFrame(packet[..^1], out _, out _));
        }
    }

    public static void FuzzNewConnectionIdFrame()
    {
        Random random = new(0x5160_2043);
        Span<byte> destination = stackalloc byte[64];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            int connectionIdLength = random.Next(1, 21);
            byte[] connectionId = RandomBytes(random, connectionIdLength);
            byte[] statelessResetToken = RandomBytes(random, 16);
            int sequenceNumber = random.Next(0, 4096);
            ulong retirePriorTo = (ulong)random.Next(0, sequenceNumber + 1);
            QuicNewConnectionIdFrame frame = new((ulong)sequenceNumber, retirePriorTo, connectionId, statelessResetToken);
            byte[] packet = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

            Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(packet, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
            Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
            Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
            Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
            Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
            Assert.Equal(packet.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(packet[..^1], out _, out _));
        }
    }

    public static void FuzzRetireConnectionIdFrame()
    {
        Random random = new(0x5160_2044);
        Span<byte> destination = stackalloc byte[16];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            QuicRetireConnectionIdFrame frame = new((ulong)random.Next(0, 4096));
            byte[] packet = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

            Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(packet, out QuicRetireConnectionIdFrame parsed, out int bytesConsumed));
            Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
            Assert.Equal(packet.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatRetireConnectionIdFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParseRetireConnectionIdFrame(packet[..^1], out _, out _));
        }
    }

    public static void FuzzPathChallengeFrame()
    {
        Random random = new(0x5160_2045);
        Span<byte> destination = stackalloc byte[16];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte[] data = RandomBytes(random, 8);
            QuicPathChallengeFrame frame = new(data);
            byte[] packet = QuicFrameTestData.BuildPathChallengeFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(packet, out QuicPathChallengeFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(packet.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParsePathChallengeFrame(packet[..^1], out _, out _));
        }
    }

    public static void FuzzPathResponseFrame()
    {
        Random random = new(0x5160_2046);
        Span<byte> destination = stackalloc byte[16];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte[] data = RandomBytes(random, 8);
            QuicPathResponseFrame frame = new(data);
            byte[] packet = QuicFrameTestData.BuildPathResponseFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathResponseFrame(packet, out QuicPathResponseFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(packet.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatPathResponseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParsePathResponseFrame(packet[..^1], out _, out _));
        }
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] data = new byte[length];
        random.NextBytes(data);
        return data;
    }
}

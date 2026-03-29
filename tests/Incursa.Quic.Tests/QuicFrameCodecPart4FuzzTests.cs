namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecPart4FuzzTests
{
    [Fact]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P12-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P12-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P12-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P12-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P13-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P13-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P13-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P13-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P13-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P13-0008")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P14-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P14-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P14-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P14-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P14-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0008")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0009")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0010")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0012")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0013")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P15-0019")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P16-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P16-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P16-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P17-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P17-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P17-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P17-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P18-0001")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P18-0002")]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FrameCodecPart4_RoundTripsRepresentativeFrameShapesAndRejectsTruncation()
    {
        Random random = new(0x5160_2040);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            switch (random.Next(7))
            {
                case 0:
                    RoundTripDataBlockedFrame(random);
                    break;
                case 1:
                    RoundTripStreamDataBlockedFrame(random);
                    break;
                case 2:
                    RoundTripStreamsBlockedFrame(random);
                    break;
                case 3:
                    RoundTripNewConnectionIdFrame(random);
                    break;
                case 4:
                    RoundTripRetireConnectionIdFrame(random);
                    break;
                case 5:
                    RoundTripPathFrame(random, isChallenge: true);
                    break;
                default:
                    RoundTripPathFrame(random, isChallenge: false);
                    break;
            }
        }
    }

    private static void RoundTripDataBlockedFrame(Random random)
    {
        QuicDataBlockedFrame frame = new((ulong)random.Next(0, 1 << 20));
        byte[] packet = QuicFrameTestData.BuildDataBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseDataBlockedFrame(packet, out QuicDataBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatDataBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseDataBlockedFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripStreamDataBlockedFrame(Random random)
    {
        QuicStreamDataBlockedFrame frame = new(
            (ulong)random.Next(0, 1 << 16),
            (ulong)random.Next(0, 1 << 20));
        byte[] packet = QuicFrameTestData.BuildStreamDataBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(packet, out QuicStreamDataBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.MaximumStreamData, parsed.MaximumStreamData);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStreamDataBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseStreamDataBlockedFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripStreamsBlockedFrame(Random random)
    {
        bool isBidirectional = random.Next(0, 2) == 0;
        ulong maximumStreams = random.Next(0, 16) == 0 ? 1UL << 60 : (ulong)random.Next(0, 1 << 20);
        QuicStreamsBlockedFrame frame = new(isBidirectional, maximumStreams);
        byte[] packet = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(packet, out QuicStreamsBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseStreamsBlockedFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripNewConnectionIdFrame(Random random)
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

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripRetireConnectionIdFrame(Random random)
    {
        QuicRetireConnectionIdFrame frame = new((ulong)random.Next(0, 4096));
        byte[] packet = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(packet, out QuicRetireConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatRetireConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseRetireConnectionIdFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripPathFrame(Random random, bool isChallenge)
    {
        byte[] data = RandomBytes(random, 8);

        if (isChallenge)
        {
            QuicPathChallengeFrame frame = new(data);
            byte[] packet = QuicFrameTestData.BuildPathChallengeFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(packet, out QuicPathChallengeFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(packet.Length, bytesConsumed);

            Span<byte> destination = stackalloc byte[16];
            Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParsePathChallengeFrame(packet[..^1], out _, out _));
        }
        else
        {
            QuicPathResponseFrame frame = new(data);
            byte[] packet = QuicFrameTestData.BuildPathResponseFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathResponseFrame(packet, out QuicPathResponseFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(packet.Length, bytesConsumed);

            Span<byte> destination = stackalloc byte[16];
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

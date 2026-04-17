namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P5-0004")]
public sealed class REQ_QUIC_RFC9000_S12P5_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_CarriesApplicationCloseInApplicationDataPackets()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: [0x6F, 0x6B]);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, payload);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
        Assert.True(packet.AsSpan(packet.Length - payload.Length, payload.Length).SequenceEqual(payload));

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1D, parsedFrame.FrameType);
        Assert.Equal(payload.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedFrame, destination, out int bytesWritten));
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(payload.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsTruncatedApplicationClosePayloads()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: [0x6F, 0x6B]);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);

        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(payload[..^1], out _, out _));
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1D], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_AllowsApplicationCloseWithoutAReasonPhrase()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: []);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1D, parsedFrame.FrameType);
        Assert.Equal(payload.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedFrame, destination, out int bytesWritten));
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(payload.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_ConnectionCloseFrame_RoundTripsApplicationErrorsInApplicationDataPackets()
    {
        Random random = new(0x5160_2080);
        Span<byte> destination = stackalloc byte[64];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte[] reasonPhrase = RandomBytes(random, random.Next(0, 32));
            ulong errorCode = (ulong)random.Next(0, 1 << 20);

            QuicConnectionCloseFrame applicationFrame = new(errorCode, reasonPhrase);
            byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);
            byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, payload);

            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
            Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
            Assert.True(parsedFrame.IsApplicationError);
            Assert.Equal((byte)0x1D, parsedFrame.FrameType);
            Assert.Equal(applicationFrame.ErrorCode, parsedFrame.ErrorCode);
            Assert.True(applicationFrame.ReasonPhrase.SequenceEqual(parsedFrame.ReasonPhrase));
            Assert.Equal(payload.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedFrame, destination, out int bytesWritten));
            Assert.Equal(payload.Length, bytesWritten);
            Assert.True(payload.AsSpan().SequenceEqual(destination[..bytesWritten]));

            if (payload.Length > 1)
            {
                Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(payload[..^1], out _, out _));
            }
        }
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] data = new byte[length];
        random.NextBytes(data);
        return data;
    }
}

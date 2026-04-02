namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecErrorHandlingFuzzTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S11-0001")]
    [Requirement("REQ-QUIC-RFC9000-S11-0002")]
    [Requirement("REQ-QUIC-RFC9000-S11-0003")]
    [Requirement("REQ-QUIC-RFC9000-S11-0004")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0003")]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_RoundTripsRepresentativeTransportAndApplicationShapes()
    {
        Random random = new(0x5160_2050);
        Span<byte> destination = stackalloc byte[64];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            bool isApplicationError = (iteration & 1) == 0;
            byte[] reasonPhrase = RandomBytes(random, random.Next(0, 32));
            ulong errorCode = (ulong)random.Next(0, 1 << 20);

            QuicConnectionCloseFrame frame = isApplicationError
                ? new QuicConnectionCloseFrame(errorCode, reasonPhrase)
                : new QuicConnectionCloseFrame(errorCode, (ulong)random.Next(0, 1 << 8), reasonPhrase);

            byte[] packet = QuicFrameTestData.BuildConnectionCloseFrame(frame);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(packet, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
            Assert.Equal(frame.IsApplicationError, parsed.IsApplicationError);
            Assert.Equal(frame.ErrorCode, parsed.ErrorCode);
            Assert.Equal(frame.HasTriggeringFrameType, parsed.HasTriggeringFrameType);
            Assert.Equal(frame.FrameType, parsed.FrameType);
            Assert.True(frame.ReasonPhrase.SequenceEqual(parsed.ReasonPhrase));

            if (!frame.IsApplicationError)
            {
                Assert.Equal(frame.TriggeringFrameType, parsed.TriggeringFrameType);
            }

            Assert.Equal(packet.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));

            if (packet.Length > 1)
            {
                Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(packet[..^1], out _, out _));
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

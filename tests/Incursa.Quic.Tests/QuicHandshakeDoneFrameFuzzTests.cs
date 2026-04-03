namespace Incursa.Quic.Tests;

public sealed class QuicHandshakeDoneFrameFuzzTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_HandshakeDoneFrame_RoundTripsAndRejectsTruncation()
    {
        Random random = new(0x5160_2080);
        Span<byte> destination = stackalloc byte[8];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte[] packet = [0x1E];
            byte[] trailingBytes = new byte[random.Next(0, 8)];
            random.NextBytes(trailingBytes);

            if (trailingBytes.Length != 0)
            {
                packet = packet.Concat(trailingBytes).ToArray();
            }

            Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(packet, out QuicHandshakeDoneFrame parsed, out int bytesConsumed));
            Assert.Equal(1, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatHandshakeDoneFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(1, bytesWritten);
            Assert.True(destination[..bytesWritten].SequenceEqual(packet[..1]));

            Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([], out _, out _));
        }
    }
}

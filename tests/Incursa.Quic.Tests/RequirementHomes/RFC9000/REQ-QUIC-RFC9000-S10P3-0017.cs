namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3-0017")]
public sealed class REQ_QUIC_RFC9000_S10P3_0017
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatNewConnectionIdFrame_WritesTheStatelessResetTokenField()
    {
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];

        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, destination, out int bytesWritten));

        ReadOnlySpan<byte> encoded = destination[..bytesWritten];
        Assert.True(encoded[^QuicStatelessReset.StatelessResetTokenLength..].SequenceEqual(statelessResetToken));

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.True(parsed.StatelessResetToken.SequenceEqual(statelessResetToken));
    }
}

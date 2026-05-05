namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0001")]
public sealed class REQ_QUIC_RFC9000_S19P6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatCryptoFrame_UsesType06ForHandshakeMessages()
    {
        byte[] handshakeBytes = [0x01, 0x00, 0x00, 0x20];
        QuicCryptoFrame frame = new(0, handshakeBytes);
        Span<byte> destination = stackalloc byte[32];

        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(frame, destination, out int bytesWritten));
        Assert.Equal(QuicS19P6CryptoFrameTestSupport.CryptoFrameType, destination[0]);
        QuicS19P6CryptoFrameTestSupport.AssertParses(destination[..bytesWritten], 0, handshakeBytes);
    }
}

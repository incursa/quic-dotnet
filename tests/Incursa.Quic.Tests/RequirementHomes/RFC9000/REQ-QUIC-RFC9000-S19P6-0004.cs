namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0004")]
public sealed class REQ_QUIC_RFC9000_S19P6_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_ParsesAndFormatsAllFields()
    {
        byte[] cryptoData = [0xAA, 0xBB, 0xCC];
        QuicCryptoFrame frame = new(0x1122_3344, cryptoData);
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(frame);

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(encoded, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.Offset, parsed.Offset);
        Assert.True(frame.CryptoData.SequenceEqual(parsed.CryptoData));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}

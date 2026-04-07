namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P5-0002")]
public sealed class REQ_QUIC_RFC9000_S7P5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAddFrame_AllowsConfiguredCapacityDuringHandshake()
    {
        QuicCryptoBuffer buffer = new(8192);
        byte[] cryptoData = new byte[5000];

        Assert.Equal(8192, buffer.Capacity);
        Assert.False(buffer.HandshakeComplete);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, cryptoData), out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);
        Assert.Equal(5000, buffer.BufferedBytes);
    }
}

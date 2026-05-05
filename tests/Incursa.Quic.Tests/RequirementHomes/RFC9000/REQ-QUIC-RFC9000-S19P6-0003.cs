namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0003")]
public sealed class REQ_QUIC_RFC9000_S19P6_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsStreamFramesWithStreamIdentifiers()
    {
        byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 4, streamData: [0xAA, 0xBB]);

        Assert.True(QuicStreamParser.TryParseStreamFrame(streamFrame, out QuicStreamFrame parsedStreamFrame));
        Assert.Equal(4UL, parsedStreamFrame.StreamId.Value);
        QuicS19P6CryptoFrameTestSupport.AssertRejects(streamFrame);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatCryptoFrame_EmitsOnlyFixedCryptoStreamFields()
    {
        byte[] cryptoData = [0xC0, 0xC1];
        byte[] expected =
        [
            .. QuicVarintTestData.EncodeMinimal(QuicS19P6CryptoFrameTestSupport.CryptoFrameType),
            .. QuicVarintTestData.EncodeMinimal(0x21),
            .. QuicVarintTestData.EncodeMinimal((ulong)cryptoData.Length),
            .. cryptoData,
        ];

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(new QuicCryptoFrame(0x21, cryptoData), destination, out int bytesWritten));
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}

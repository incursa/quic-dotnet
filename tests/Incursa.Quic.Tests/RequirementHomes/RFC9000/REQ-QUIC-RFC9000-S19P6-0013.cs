namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0013")]
public sealed class REQ_QUIC_RFC9000_S19P6_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatCryptoFrame_UsesTypeWithoutFinBit()
    {
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA]));

        Assert.Equal(QuicS19P6CryptoFrameTestSupport.CryptoFrameType, encoded[0]);
        Assert.Equal(0, encoded[0] & 0x01);
        QuicS19P6CryptoFrameTestSupport.AssertParses(encoded, 0, [0xAA]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsStreamFrameWithFinBit()
    {
        byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 0, streamData: [0xAA]);

        Assert.True(QuicStreamParser.TryParseStreamFrame(streamFrame, out QuicStreamFrame parsedStreamFrame));
        Assert.True(parsedStreamFrame.IsFin);
        QuicS19P6CryptoFrameTestSupport.AssertRejects(streamFrame);
    }
}

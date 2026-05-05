namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0010")]
public sealed class REQ_QUIC_RFC9000_S19P6_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_AcceptsFramesThatExactlyReachTheStreamCeiling()
    {
        byte[] cryptoData = [0xAB];
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue - 1, cryptoData));

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(encoded, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, parsed.Offset);
        Assert.True(cryptoData.AsSpan().SequenceEqual(parsed.CryptoData));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsFramesThatPassTheStreamCeiling()
    {
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue, [0xAB]));

        QuicS19P6CryptoFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseCryptoFrame_AcceptsMaximumOffsetWhenLengthIsZero()
    {
        byte[] encoded = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(
            QuicVariableLengthInteger.MaxValue,
            declaredLength: 0,
            cryptoData: []);

        QuicS19P6CryptoFrameTestSupport.AssertParses(encoded, QuicVariableLengthInteger.MaxValue, []);
    }
}

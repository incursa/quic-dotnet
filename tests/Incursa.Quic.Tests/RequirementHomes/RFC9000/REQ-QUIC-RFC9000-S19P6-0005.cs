namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0005")]
public sealed class REQ_QUIC_RFC9000_S19P6_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_ConsumesVariableLengthOffsetField()
    {
        byte[] frame = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithEncodedOffset(
            offset: 0x1122,
            encodedOffsetLength: 2,
            cryptoData: [0xAA]);

        QuicS19P6CryptoFrameTestSupport.AssertParses(frame, 0x1122, [0xAA]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsTruncatedOffsetVarint()
    {
        QuicS19P6CryptoFrameTestSupport.AssertRejects([QuicS19P6CryptoFrameTestSupport.CryptoFrameType, 0x40]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseCryptoFrame_AcceptsLargestOffsetWithEmptyCryptoData()
    {
        byte[] frame = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(
            QuicVariableLengthInteger.MaxValue,
            declaredLength: 0,
            cryptoData: []);

        QuicS19P6CryptoFrameTestSupport.AssertParses(frame, QuicVariableLengthInteger.MaxValue, []);
    }
}

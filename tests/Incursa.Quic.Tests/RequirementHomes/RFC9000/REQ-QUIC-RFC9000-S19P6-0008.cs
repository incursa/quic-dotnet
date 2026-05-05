namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0008")]
public sealed class REQ_QUIC_RFC9000_S19P6_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_MapsOffsetToCryptoDataPosition()
    {
        byte[] frame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0x1234, [0xAA, 0xBB]));

        QuicS19P6CryptoFrameTestSupport.AssertParses(frame, 0x1234, [0xAA, 0xBB]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsOffsetAndLengthBeyondCryptoStreamLimit()
    {
        byte[] frame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue, [0xAA]));

        QuicS19P6CryptoFrameTestSupport.AssertRejects(frame);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseCryptoFrame_AcceptsMaximumOffsetWithNoCryptoData()
    {
        byte[] frame = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(
            QuicVariableLengthInteger.MaxValue,
            declaredLength: 0,
            cryptoData: []);

        QuicS19P6CryptoFrameTestSupport.AssertParses(frame, QuicVariableLengthInteger.MaxValue, []);
    }
}

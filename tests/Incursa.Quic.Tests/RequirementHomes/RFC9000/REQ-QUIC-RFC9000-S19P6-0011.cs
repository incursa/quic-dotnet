namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0011")]
public sealed class REQ_QUIC_RFC9000_S19P6_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue, [0xAA]));

        Assert.False(QuicFrameCodec.TryParseCryptoFrame(encoded, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        QuicCryptoFrame frame = new(QuicVariableLengthInteger.MaxValue, [0xAA]);

        Assert.False(QuicFrameCodec.TryFormatCryptoFrame(frame, stackalloc byte[16], out _));
    }
}

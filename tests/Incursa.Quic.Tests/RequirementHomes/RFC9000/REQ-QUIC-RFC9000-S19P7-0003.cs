namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0003")]
public sealed class REQ_QUIC_RFC9000_S19P7_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewTokenFrame_ConsumesTheRequiredTypeLengthAndTokenFields()
    {
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken);

        QuicS19P7NewTokenFrameTestSupport.AssertParses(
            encoded,
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken,
            expectedBytesConsumed: encoded.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewTokenFrame_RejectsPayloadsThatAreMissingRequiredFields()
    {
        Assert.False(QuicFrameCodec.TryParseNewTokenFrame([0x07], out _, out _));
        Assert.False(QuicFrameCodec.TryParseNewTokenFrame([0x07, 0x01], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewTokenFrame_StopsAfterTheTokenBeforeATrailingFrame()
    {
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrameWithTrailingPing(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken);

        QuicS19P7NewTokenFrameTestSupport.AssertParses(
            encoded,
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken,
            expectedBytesConsumed: encoded.Length - 1);
    }
}

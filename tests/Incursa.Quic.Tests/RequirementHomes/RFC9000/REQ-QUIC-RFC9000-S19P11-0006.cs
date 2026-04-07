namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P11-0006")]
public sealed class REQ_QUIC_RFC9000_S19P11_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxStreamsFrame_RejectsValuesAboveTheEncodingLimit()
    {
        QuicMaxStreamsFrame invalidFrame = new(true, (1UL << 60) + 1);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(invalidFrame);
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatMaxStreamsFrame(invalidFrame, destination, out _));
    }
}

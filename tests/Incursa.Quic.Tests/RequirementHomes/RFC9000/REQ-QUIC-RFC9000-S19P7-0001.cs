namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0001")]
public sealed class REQ_QUIC_RFC9000_S19P7_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatNewTokenFrame_WritesTheFrameTypeField()
    {
        QuicNewTokenFrame frame = new([0x10, 0x20, 0x30, 0x40]);
        Span<byte> destination = stackalloc byte[16];

        Assert.True(QuicFrameCodec.TryFormatNewTokenFrame(frame, destination, out int bytesWritten));
        Assert.Equal(6, bytesWritten);
        Assert.Equal(0x07, destination[0]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewTokenFrame_RejectsOtherFrameTypes()
    {
        byte[] encoded = [0x08, 0x01, 0xAA];

        QuicS19P7NewTokenFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewTokenFrame_RejectsNonMinimalFrameTypeEncoding()
    {
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrameWithEncodedFrameType(
            [0x40, 0x07],
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken);

        QuicS19P7NewTokenFrameTestSupport.AssertRejects(encoded);
    }
}

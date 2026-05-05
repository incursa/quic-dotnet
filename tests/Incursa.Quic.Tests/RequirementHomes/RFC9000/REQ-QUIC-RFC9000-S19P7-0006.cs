namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0006")]
public sealed class REQ_QUIC_RFC9000_S19P7_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatNewTokenFrame_AcceptsNonEmptyTokens()
    {
        QuicNewTokenFrame frame = new([0xA5]);
        Span<byte> destination = stackalloc byte[8];

        Assert.True(QuicFrameCodec.TryFormatNewTokenFrame(frame, destination, out int bytesWritten));
        Assert.Equal(3, bytesWritten);
        Assert.Equal(0x07, destination[0]);
        Assert.Equal(0x01, destination[1]);
        Assert.Equal(0xA5, destination[2]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatNewTokenFrame_RejectsEmptyTokens()
    {
        QuicNewTokenFrame emptyFrame = new(Array.Empty<byte>());
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryFormatNewTokenFrame(emptyFrame, destination, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewTokenFrame_AcceptsTheShortestNonEmptyToken()
    {
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame([0x01]);

        QuicS19P7NewTokenFrameTestSupport.AssertParses(encoded, [0x01], expectedBytesConsumed: encoded.Length);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0006")]
public sealed class REQ_QUIC_RFC9000_S19P7_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatNewTokenFrame_RejectsEmptyTokens()
    {
        QuicNewTokenFrame emptyFrame = new(Array.Empty<byte>());
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryFormatNewTokenFrame(emptyFrame, destination, out _));
    }
}

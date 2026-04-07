namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0007")]
public sealed class REQ_QUIC_RFC9000_S19P7_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewTokenFrame_RejectsEmptyTokens()
    {
        QuicNewTokenFrame emptyFrame = new(Array.Empty<byte>());
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(emptyFrame);

        Assert.False(QuicFrameCodec.TryParseNewTokenFrame(encoded, out _, out _));
    }
}

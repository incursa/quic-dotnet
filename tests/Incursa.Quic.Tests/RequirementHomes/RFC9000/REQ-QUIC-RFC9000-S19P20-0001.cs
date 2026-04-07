namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P20-0001")]
public sealed class REQ_QUIC_RFC9000_S19P20_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseHandshakeDoneFrame_RecognizesTheHandshakeDoneType()
    {
        byte[] encoded = QuicFrameTestData.BuildHandshakeDoneFrame();

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(encoded, out _, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

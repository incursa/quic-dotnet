namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0004")]
public sealed class REQ_QUIC_RFC9000_S19P7_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewTokenFrame_UsesTheTokenLengthFieldToRecoverTheWholeToken()
    {
        byte[] token = new byte[64];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = (byte)index;
        }

        QuicNewTokenFrame frame = new(token);
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(encoded, out QuicNewTokenFrame parsed, out int bytesConsumed));
        Assert.Equal(token.Length, parsed.Token.Length);
        Assert.True(token.AsSpan().SequenceEqual(parsed.Token));
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

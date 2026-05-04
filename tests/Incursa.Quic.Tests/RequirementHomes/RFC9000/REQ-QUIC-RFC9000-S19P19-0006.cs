namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0006")]
public sealed class REQ_QUIC_RFC9000_S19P19_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_PreservesVariableLengthReasonPhraseLength()
    {
        byte[] reasonPhrase = [0x6F, 0x6B, 0x21];
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(reasonPhrase: reasonPhrase);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(reasonPhrase.Length, parsed.ReasonPhrase.Length);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsReasonPhraseLengthBeyondThePayload()
    {
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1C, 0x00, 0x00, 0x02, 0xAA], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_PreservesTwoByteVariableLengthReasonPhraseLength()
    {
        byte[] reasonPhrase = Enumerable.Repeat((byte)0x51, 64).ToArray();
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(reasonPhrase: reasonPhrase);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(64, parsed.ReasonPhrase.Length);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

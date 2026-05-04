namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0002")]
public sealed class REQ_QUIC_RFC9000_S19P19_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_UsesTheApplicationCloseFrameTypeForApplicationErrors()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(
            errorCode: 0x1234,
            reasonPhrase: [0x61, 0x70, 0x70]);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.Equal(0x1234UL, parsed.ErrorCode);
        Assert.False(parsed.HasTriggeringFrameType);
        Assert.True(parsed.ReasonPhrase.SequenceEqual(new byte[] { 0x61, 0x70, 0x70 }));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_DoesNotClassifyTransportCloseAsApplicationClose()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: (ulong)QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0x02,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.NotEqual((byte)0x1D, parsed.FrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

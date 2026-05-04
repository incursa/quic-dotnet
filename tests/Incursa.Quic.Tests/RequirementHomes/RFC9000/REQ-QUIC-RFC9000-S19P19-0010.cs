namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0010")]
public sealed class REQ_QUIC_RFC9000_S19P19_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_PreservesApplicationProtocolErrorCodesOnApplicationCloseFrames()
    {
        const ulong applicationProtocolErrorCode = 0x1234;
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(
            errorCode: applicationProtocolErrorCode,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.Equal(applicationProtocolErrorCode, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

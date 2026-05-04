namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0009")]
public sealed class REQ_QUIC_RFC9000_S19P19_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_PreservesTransportErrorCodesOnTransportCloseFrames()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: (ulong)QuicTransportErrorCode.FrameEncodingError,
            triggeringFrameType: 0x19,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.FrameEncodingError, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

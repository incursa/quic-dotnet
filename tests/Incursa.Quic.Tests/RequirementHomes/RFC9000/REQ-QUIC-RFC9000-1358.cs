namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1358")]
public sealed class REQ_QUIC_RFC9000_1358
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_DoesNotUseTransportErrorCodeSpaceForApplicationCloseFrames()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(
            errorCode: (ulong)QuicTransportErrorCode.FrameEncodingError,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.False(parsed.HasTriggeringFrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.FrameEncodingError, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

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

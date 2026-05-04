namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0007")]
public sealed class REQ_QUIC_RFC9000_S19P19_0007
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_ParsesTheRequiredFields(bool isApplicationError)
    {
        byte[] reasonPhrase = [0x6F, 0x6B];
        byte[] encoded = isApplicationError
            ? QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode: 0x1234, reasonPhrase)
            : QuicConnectionCloseFrameProofSupport.BuildTransportClose(errorCode: 0x1234, triggeringFrameType: 0x02, reasonPhrase);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(isApplicationError, parsed.IsApplicationError);
        Assert.Equal(0x1234UL, parsed.ErrorCode);
        Assert.Equal(!isApplicationError, parsed.HasTriggeringFrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

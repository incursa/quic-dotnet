namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1361")]
public sealed class REQ_QUIC_RFC9000_1361
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_ApplicationCloseOmitsTheTriggeringFrameType()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode: 0x1234, reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.False(parsed.HasTriggeringFrameType);
        Assert.Equal(0UL, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatConnectionCloseFrame_ApplicationCloseIsShorterThanTransportCloseWithATriggeringFrameType()
    {
        byte[] applicationClose = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode: 0, reasonPhrase: []);
        byte[] transportClose = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: 0,
            triggeringFrameType: 0x02,
            reasonPhrase: []);

        Assert.Equal(3, applicationClose.Length);
        Assert.Equal(4, transportClose.Length);
        Assert.DoesNotContain((byte)0x02, applicationClose);
    }
}

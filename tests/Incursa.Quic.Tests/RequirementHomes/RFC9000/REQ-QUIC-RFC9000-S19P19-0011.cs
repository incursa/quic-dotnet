namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0011")]
public sealed class REQ_QUIC_RFC9000_S19P19_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_PreservesTheTriggeringFrameType()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(triggeringFrameType: 0x1A, reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.HasTriggeringFrameType);
        Assert.Equal(0x1AUL, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsMissingTriggeringFrameType()
    {
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1C, 0x00], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_PreservesPaddingAsTheUnknownTriggeringFrameType()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(triggeringFrameType: 0, reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(0UL, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

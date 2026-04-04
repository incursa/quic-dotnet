namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P4-0003")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IsAckElicitingFrameType_RecognizesPingAsAckEliciting()
    {
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x01));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IsAckElicitingFrameType_RejectsPaddingAndAckFrames()
    {
        Assert.False(QuicFrameCodec.IsAckElicitingFrameType(0x00));
        Assert.False(QuicFrameCodec.IsAckElicitingFrameType(0x02));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IsAckElicitingFrameType_RejectsConnectionCloseFrames()
    {
        Assert.False(QuicFrameCodec.IsAckElicitingFrameType(0x1C));
        Assert.False(QuicFrameCodec.IsAckElicitingFrameType(0x1D));
    }
}

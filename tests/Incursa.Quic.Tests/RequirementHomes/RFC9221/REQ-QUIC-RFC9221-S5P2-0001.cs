namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S5P2-0001")]
public sealed class REQ_QUIC_RFC9221_S5P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IsAckElicitingFrameType_TreatsDatagramFramesAsAckEliciting()
    {
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x30));
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x31));
    }
}

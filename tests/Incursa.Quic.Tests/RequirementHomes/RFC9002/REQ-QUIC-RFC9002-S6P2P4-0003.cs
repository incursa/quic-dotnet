namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P4-0003")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryKeepPtoProbePacketsAckEliciting_RecognizesPingAsAckEliciting()
    {
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x01));
    }
}

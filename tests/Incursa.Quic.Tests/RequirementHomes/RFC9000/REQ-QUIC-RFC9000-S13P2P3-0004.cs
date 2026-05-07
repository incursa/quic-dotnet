namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P2P3-0004")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_LimitsRetainedAckRanges()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(maximumRetainedAckRanges: 1);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsSingleRangeAckFrame(tracker);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P2P3-0003")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_OmitsTheOldestRangeWhenTheLimitIsExceeded()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(maximumRetainedAckRanges: 2);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsTrimmedAckFrame(tracker);
    }
}

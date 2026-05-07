namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P2P3-0002")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_AcknowledgesTheMostRecentlyReceivedPackets()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(maximumRetainedAckRanges: 3);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsThreeRangeAckFrame(tracker);
    }
}

namespace Incursa.Quic.Tests;

[workbench-requirements generated="true" source="workbench quality sync"]
/// <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0004">A receiver MUST limit the number of ACK Ranges it remembers and sends in ACK frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P3-0004")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_TrimsOldestRangesWhenLimitReached()
    {
        QuicAckGenerationState keepTwoRanges = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(2);
        QuicS13P2P3AckFrameProofSupport.AssertBuildsTrimmedAckFrame(keepTwoRanges);

        QuicAckGenerationState keepOnlyLargestRange = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(1);
        QuicS13P2P3AckFrameProofSupport.AssertBuildsSingleRangeAckFrame(keepOnlyLargestRange);
    }
}

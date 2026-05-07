namespace Incursa.Quic.Tests;

[workbench-requirements generated="true" source="workbench quality sync"]
/// <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0007">A receiver MAY discard unacknowledged ACK Ranges to limit ACK frame size.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P3-0007")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_KeepsAllRangesWhenTheConfiguredLimitIsSufficient()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(3, 1, 2, 5, 6, 9);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 9,
            expectedFirstAckRange: 0,
            new QuicAckRange(1, 1, 5, 6),
            new QuicAckRange(1, 1, 1, 2));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_DropsOlderRangesWhenOnlyOneRangeCanBeRetained()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(1, 1, 2, 5, 6, 9);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 9,
            expectedFirstAckRange: 0);
    }
}

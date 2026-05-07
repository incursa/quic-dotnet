namespace Incursa.Quic.Tests;

[workbench-requirements generated="true" source="workbench quality sync"]
/// <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0011">Receivers MAY discard all ACK Ranges if they retain the largest packet number that has been successfully processed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P3-0011")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_DoesNotDiscardEveryRangeWhenMoreThanOneRangeIsRetained()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(2, 1, 2, 5, 6, 9);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 9,
            expectedFirstAckRange: 0,
            new QuicAckRange(1, 1, 5, 6));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_CanDiscardAllOlderRangesWhenOnlyTheLargestPacketNumberIsRetained()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(1, 1, 2, 5, 6, 9);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 9,
            expectedFirstAckRange: 0);
    }
}

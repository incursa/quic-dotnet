namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
/// <workbench-requirement requirementId="REQ-QUIC-RFC9000-13233">A receiver MUST limit the number of ACK Ranges it remembers and sends in ACK frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-13233")]
public sealed class REQ_QUIC_RFC9000_13233
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_DoesNotEmitMoreRangesThanTheConfiguredLimit()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(
            maximumRetainedAckRanges: 2,
            1,
            3,
            5,
            7,
            9,
            11);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(11UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(9UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(9UL, frame.AdditionalRanges[0].LargestAcknowledged);
    }
}

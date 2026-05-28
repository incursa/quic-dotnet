// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
/// <workbench-requirement requirementId="REQ-QUIC-RFC9000-0771">A receiver SHOULD include an ACK Range containing the largest received packet number in every ACK frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0771")]
public sealed class REQ_QUIC_RFC9000_0771
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_ReportsTheLargestReceivedPacketNumber()
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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_DoesNotReportAnOlderPacketNumberAsLargestAcknowledged()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(2, 1, 2, 5, 6, 9);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.NotEqual(6UL, frame.LargestAcknowledged);
        Assert.NotEqual(5UL, frame.LargestAcknowledged);
        Assert.Equal(9UL, frame.LargestAcknowledged);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_PreservesTheLargestReceivedPacketNumberWhenOnlyOnePacketWasObserved()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(1, 9);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(tracker, expectedLargestAcknowledged: 9, expectedFirstAckRange: 0);
    }
}

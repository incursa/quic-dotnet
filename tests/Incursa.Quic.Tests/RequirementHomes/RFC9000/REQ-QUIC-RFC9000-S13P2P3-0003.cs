// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
/// <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0003">If it MUST NOT, then older ranges (those with the smallest packet numbers) are omitted.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P3-0003")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_OmitsTheOldestRangeWhenTheLimitIsExceeded()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(2, 1, 2, 5, 6, 9);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 9,
            expectedFirstAckRange: 0,
            new QuicAckRange(1, 1, 5, 6));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_KeepsOlderRangesWhenTheConfiguredLimitStillFits()
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
    public void TryBuildAckFrame_LeavesASingleRangeWhenNoOlderRangesExist()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(1, 1, 2, 5, 6, 9);

        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 9,
            expectedFirstAckRange: 0);
    }
}

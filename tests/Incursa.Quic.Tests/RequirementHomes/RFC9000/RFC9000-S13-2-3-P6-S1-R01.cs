// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
/// <workbench-requirement requirementId="RFC9000-S13-2-3-P6-S1-R01">Receivers can discard all ACK Ranges, but they MUST retain the largest packet number that has been successfully processed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S13-2-3-P6-S1-R01")]
public sealed class RFC9000_S13_2_3_P6_S1_R01
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

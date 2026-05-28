// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P2P3-0013")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0013
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_FollowsTheExemplaryPacketSelectionApproach()
    {
        QuicS13P2P3AckFrameProofSupport.AssertBuildsTrimmedAckFrame(
            QuicS13P2P3AckFrameProofSupport.CreateTrackedState(maximumRetainedAckRanges: 2));
    }
}

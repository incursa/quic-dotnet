// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0004">A request to update the date on any provisional registration MAY be made without review from the designated expert(s).</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0004")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ProvisionalDateUpdates_DoNotRequireExpertReview()
    {
        Assert.False(QuicIanaRegistrationPolicy.ProvisionalDateUpdateRequiresExpertReview);
    }
}

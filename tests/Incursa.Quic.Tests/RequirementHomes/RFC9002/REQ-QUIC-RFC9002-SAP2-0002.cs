// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP2-0002">kTimeThreshold SHOULD be 9/8.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP2-0002")]
public sealed class REQ_QUIC_RFC9002_SAP2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecommendedTimeThreshold_UsesNineOverEight()
    {
        Assert.Equal(9UL, QuicRecoveryTiming.RecommendedTimeThresholdNumerator);
        Assert.Equal(8UL, QuicRecoveryTiming.RecommendedTimeThresholdDenominator);
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S7-3-2-P3-S1-R01">Implementations MAY reduce the congestion window immediately upon entering a recovery period or use other mechanisms, such as Proportional Rate Reduction, to reduce the congestion window more gradually.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S7-3-2-P3-S1-R01")]
public sealed class REQ_QUIC_RFC9002_S7P3P2_0005
{
    [Theory]
    [InlineData(12_000UL, 7UL, 8UL, 2_400UL, 10_500UL)]
    [InlineData(1_000UL, 7UL, 8UL, 2_400UL, 2_400UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ComputeReducedCongestionWindowBytes_UsesAGentlerReductionFactorAndHonorsMinimumWindow(
        ulong congestionWindowBytes,
        ulong reductionNumerator,
        ulong reductionDenominator,
        ulong minimumCongestionWindowBytes,
        ulong expectedReducedCongestionWindowBytes)
    {
        Assert.Equal(expectedReducedCongestionWindowBytes, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
            congestionWindowBytes,
            reductionNumerator: reductionNumerator,
            reductionDenominator: reductionDenominator,
            minimumCongestionWindowBytes: minimumCongestionWindowBytes));
    }
}

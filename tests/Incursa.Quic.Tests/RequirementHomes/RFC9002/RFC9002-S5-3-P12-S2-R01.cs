// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S5-3-P12-S2-R01">`rttvar` is initialized to `kInitialRtt / 2`.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S5-3-P12-S2-R01")]
public sealed class RFC9002_S5_3_P12_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void Constructor_InitializesRttVariationToHalfTheConfiguredInitialRtt()
    {
        QuicRttEstimator estimator = new(initialRttMicros: 123_000);

        Assert.False(estimator.HasRttSample);
        Assert.Equal(61_500UL, estimator.RttVarMicros);
    }
}

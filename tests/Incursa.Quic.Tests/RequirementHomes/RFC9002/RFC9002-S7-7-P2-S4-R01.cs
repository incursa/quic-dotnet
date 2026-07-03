// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S7-7-P2-S4-R01">A sender with knowledge that the network path can absorb larger bursts MAY use a higher limit.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S7-7-P2-S4-R01")]
public sealed class REQ_QUIC_RFC9002_S7P7_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetBurstLimitBytes_UsesTheHigherLimitWhenThePathCanAbsorbLargerBursts()
    {
        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: true,
            out ulong burstLimitBytes,
            largerBurstLimitBytes: 24_000));

        Assert.Equal(24_000UL, burstLimitBytes);
    }
}

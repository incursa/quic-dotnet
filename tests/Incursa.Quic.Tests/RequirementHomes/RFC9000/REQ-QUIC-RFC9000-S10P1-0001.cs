// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0001">To avoid excessively small idle timeout periods, endpoints MUST increase the idle timeout period to be at least three times the current Probe Timeout (PTO).</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P1-0001")]
public sealed class REQ_QUIC_RFC9000_S10P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeEffectiveIdleTimeoutMicros_RejectsAZeroProbeTimeout()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: 18,
            peerMaxIdleTimeoutMicros: null,
            currentProbeTimeoutMicros: 0,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryComputeEffectiveIdleTimeoutMicros_LeavesTheIdleTimeoutAtTheThreeTimesPtoBoundary()
    {
        Assert.True(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: 18,
            peerMaxIdleTimeoutMicros: null,
            currentProbeTimeoutMicros: 6,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(18UL, effectiveIdleTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryComputeEffectiveIdleTimeoutMicros_FuzzAppliesThreeTimesPtoFloor()
    {
        (ulong AdvertisedIdleTimeoutMicros, ulong ProbeTimeoutMicros)[] scenarios =
        [
            (1, 1),
            (18, 6),
            (19, 6),
            (100, 50),
            (ulong.MaxValue - 1, ulong.MaxValue),
        ];

        foreach ((ulong advertisedIdleTimeoutMicros, ulong probeTimeoutMicros) in scenarios)
        {
            Assert.True(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
                advertisedIdleTimeoutMicros,
                peerMaxIdleTimeoutMicros: null,
                probeTimeoutMicros,
                out ulong effectiveIdleTimeoutMicros));

            ulong expectedFloor = probeTimeoutMicros > ulong.MaxValue / 3 ? ulong.MaxValue : probeTimeoutMicros * 3;
            Assert.Equal(Math.Max(advertisedIdleTimeoutMicros, expectedFloor), effectiveIdleTimeoutMicros);
        }
    }
}

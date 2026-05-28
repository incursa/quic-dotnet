// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0554">Endpoints MUST increase the idle timeout period to be at least three times the current Probe Timeout (PTO).</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0554")]
public sealed class REQ_QUIC_RFC9000_0554
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeEffectiveIdleTimeoutMicros_RejectsAZeroProbeTimeout()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: null,
            peerMaxIdleTimeoutMicros: 18,
            currentProbeTimeoutMicros: 0,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryComputeEffectiveIdleTimeoutMicros_SaturatesThePtoFloorAtUlongMaxValue()
    {
        ulong currentProbeTimeoutMicros = (ulong.MaxValue / 3) + 1;

        Assert.True(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: 1,
            peerMaxIdleTimeoutMicros: null,
            currentProbeTimeoutMicros: currentProbeTimeoutMicros,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(ulong.MaxValue, effectiveIdleTimeoutMicros);
    }
}

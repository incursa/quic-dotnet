// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S7-5-P1-S1-R01">Probe packets MUST NOT be blocked by the congestion controller.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S7-5-P1-S1-R01")]
public sealed class REQ_QUIC_RFC9002_S7P5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    public void CanSend_StillAllowsProbePacketsWhenTheCongestionWindowIsFull()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.False(state.CanSend(1, isAckOnlyPacket: false, isProbePacket: false));
        Assert.True(state.CanSend(1, isProbePacket: true));
    }
}

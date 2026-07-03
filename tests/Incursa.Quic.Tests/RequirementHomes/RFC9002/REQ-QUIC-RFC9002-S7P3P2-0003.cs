// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S7-3-2-P2-S1-R01">On entering a recovery period, a sender MUST set the slow start threshold to half the congestion window when loss is detected.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S7-3-2-P2-S1-R01")]
public sealed class REQ_QUIC_RFC9002_S7P3P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryRegisterLoss_HonorsTheMinimumCongestionWindowWhenRecoveryWouldCutBelowIt()
    {
        QuicCongestionControlState state = new(10_000);
        state.RegisterPacketSent(20_000);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 20_000,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.Equal(state.MinimumCongestionWindowBytes, state.SlowStartThresholdBytes);
        Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterLoss_DoesNotCutTheSlowStartThresholdForIneligibleSignals()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.False(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: false));

        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
    }
}

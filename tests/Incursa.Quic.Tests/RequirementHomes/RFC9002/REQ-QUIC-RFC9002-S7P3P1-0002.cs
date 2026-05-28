// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P3P1-0002")]
public sealed class REQ_QUIC_RFC9002_S7P3P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void IsInSlowStart_TreatsEqualityWithTheThresholdAsCongestionAvoidance()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.Equal(state.SlowStartThresholdBytes, state.CongestionWindowBytes);
        Assert.False(state.IsInSlowStart);
        Assert.True(state.IsInCongestionAvoidance);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
    public void IsInSlowStartFollowsTheCongestionWindowThresholdRelationship()
    {
        QuicCongestionControlState state = new();

        Assert.True(state.IsInSlowStart);
        Assert.False(state.IsInCongestionAvoidance);

        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.False(state.IsInSlowStart);
        Assert.True(state.IsInCongestionAvoidance);
        Assert.Equal(state.CongestionWindowBytes, state.SlowStartThresholdBytes);
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S7-8-P1-S3-R01">When bytes in flight is smaller than the congestion window and sending is not pacing limited, the congestion window SHOULD NOT be increased in either slow start or congestion avoidance.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S7-8-P1-S3-R01")]
public sealed class RFC9002_S7_8_P1_S3_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterAcknowledgedPacket_LeavesTheWindowUnchangedWhenTheSenderIsNotPacingLimited()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: false));

        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.False(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterAcknowledgedPacket_GrowsTheWindowWhenTheSameStateIsPacingLimited()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: true));

        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.Equal(13_200UL, state.CongestionWindowBytes);
    }
}

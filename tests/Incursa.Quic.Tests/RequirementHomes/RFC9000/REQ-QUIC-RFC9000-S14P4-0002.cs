// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P4-0002")]
public sealed class REQ_QUIC_RFC9000_S14P4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterLoss_IgnoresProbePacketLossForCongestionControl()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200, isProbePacket: true);
        Assert.Equal(1_200UL, state.BytesInFlightBytes);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true,
            isProbePacket: true));

        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
    }
}

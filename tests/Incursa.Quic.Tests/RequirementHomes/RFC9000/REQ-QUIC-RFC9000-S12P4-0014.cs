// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P4-0014")]
public sealed class REQ_QUIC_RFC9000_S12P4_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RegisterPacketSent_DoesNotIncreaseBytesInFlightForCMarkedPackets()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200, isAckOnlyPacket: true);

        Assert.Equal(0UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RegisterPacketSent_CountsPacketsWithoutTheCMarkingTowardBytesInFlight()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200, isAckOnlyPacket: false);

        Assert.Equal(1_200UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RegisterPacketSent_DoesNotIncreaseBytesInFlightForCMarkedPacketsAtTheCongestionWindowLimit()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        state.RegisterPacketSent(1_200, isAckOnlyPacket: true);

        Assert.Equal(state.CongestionWindowBytes, state.BytesInFlightBytes);
    }
}

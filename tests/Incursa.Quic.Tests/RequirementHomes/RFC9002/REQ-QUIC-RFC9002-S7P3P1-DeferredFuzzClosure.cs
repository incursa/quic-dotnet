// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S7P3P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P3P1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SlowStartFollowsCongestionWindowThresholdRelationship()
    {
        foreach (ulong lostPacketBytes in new[] { 1UL, 64UL, 1_200UL, 2_400UL })
        {
            QuicCongestionControlState state = new();

            Assert.True(state.IsInSlowStart);
            Assert.False(state.IsInCongestionAvoidance);

            state.RegisterPacketSent(lostPacketBytes);
            Assert.True(state.TryRegisterLoss(
                sentBytes: lostPacketBytes,
                sentAtMicros: 1_000,
                packetInFlight: true));

            Assert.Equal(state.SlowStartThresholdBytes, state.CongestionWindowBytes);
            Assert.False(state.IsInSlowStart);
            Assert.True(state.IsInCongestionAvoidance);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P3P1-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AcknowledgmentsGrowCongestionWindowByAckedBytesInSlowStart()
    {
        foreach (ulong acknowledgedBytes in new[] { 1UL, 64UL, 1_200UL, 2_400UL })
        {
            QuicCongestionControlState state = new();
            ulong initialCongestionWindowBytes = state.CongestionWindowBytes;
            state.RegisterPacketSent(acknowledgedBytes * 2);

            Assert.True(state.TryRegisterAcknowledgedPacket(
                sentBytes: acknowledgedBytes,
                sentAtMicros: 1_000,
                packetInFlight: true,
                pacingLimited: true));

            Assert.Equal(initialCongestionWindowBytes + acknowledgedBytes, state.CongestionWindowBytes);
            Assert.Equal(acknowledgedBytes, state.BytesInFlightBytes);
            Assert.True(state.IsInSlowStart);
        }
    }
}

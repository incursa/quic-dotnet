// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S7P3P3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P3P3-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SenderEntersCongestionAvoidanceWhenWindowReachesThresholdOutsideRecovery()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong lostBytes, ulong acknowledgedBytes) in new[]
        {
            (1_200UL, 1_200UL, 1_200UL),
            (1_472UL, 1_472UL, 736UL),
            (2_400UL, 2_400UL, 1_200UL),
            (4_096UL, 4_096UL, 2_048UL),
        })
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);
            ulong initialCongestionWindowBytes = state.CongestionWindowBytes;

            state.RegisterPacketSent(initialCongestionWindowBytes);
            state.RegisterPacketSent(acknowledgedBytes);

            Assert.True(state.TryRegisterLoss(
                sentBytes: lostBytes,
                sentAtMicros: 1_000,
                packetInFlight: true));
            Assert.True(state.HasRecoveryStartTime);
            Assert.True(state.CongestionWindowBytes >= state.SlowStartThresholdBytes);

            Assert.True(state.TryRegisterAcknowledgedPacket(
                sentBytes: acknowledgedBytes,
                sentAtMicros: 2_000,
                packetInFlight: true,
                applicationLimited: true));

            Assert.False(state.HasRecoveryStartTime);
            Assert.False(state.IsInSlowStart);
            Assert.True(state.IsInCongestionAvoidance);
            Assert.True(state.CongestionWindowBytes >= state.SlowStartThresholdBytes);
        }
    }
}

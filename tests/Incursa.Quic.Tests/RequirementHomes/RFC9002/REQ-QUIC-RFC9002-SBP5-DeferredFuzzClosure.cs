// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SBP5_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP5-0001")]
    [Requirement("REQ-QUIC-RFC9002-SBP5-0002")]
    [Requirement("REQ-QUIC-RFC9002-SBP5-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryRegisterAcknowledgedPacket_RemovesInFlightBytesAndGrowsInSlowStart()
    {
        foreach (ulong ackedBytes in new ulong[] { 1, 1_200, 2_400, 6_000 })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);
            state.RegisterPacketSent(ackedBytes, isProbePacket: true);

            Assert.False(state.TryRegisterAcknowledgedPacket(
                sentBytes: ackedBytes,
                sentAtMicros: 1_000,
                packetInFlight: false));
            Assert.Equal(12_000UL + ackedBytes, state.BytesInFlightBytes);
            Assert.Equal(12_000UL, state.CongestionWindowBytes);

            Assert.True(state.TryRegisterAcknowledgedPacket(
                sentBytes: ackedBytes,
                sentAtMicros: 1_000,
                packetInFlight: true));

            Assert.Equal(12_000UL, state.BytesInFlightBytes);
            Assert.Equal(12_000UL + ackedBytes, state.CongestionWindowBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP5-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryRegisterAcknowledgedPacket_SuppressesWindowGrowthWhenSenderIsLimited()
    {
        foreach ((bool applicationLimited, bool flowControlLimited) in new[]
        {
            (true, false),
            (false, true),
            (true, true),
        })
        {
            foreach (ulong ackedBytes in new ulong[] { 1_200, 2_400, 6_000 })
            {
                QuicCongestionControlState state = new();
                state.RegisterPacketSent(12_000);
                state.RegisterPacketSent(ackedBytes, isProbePacket: true);

                Assert.True(state.TryRegisterAcknowledgedPacket(
                    sentBytes: ackedBytes,
                    sentAtMicros: 1_000,
                    packetInFlight: true,
                    applicationLimited: applicationLimited,
                    flowControlLimited: flowControlLimited));

                Assert.Equal(12_000UL, state.BytesInFlightBytes);
                Assert.Equal(12_000UL, state.CongestionWindowBytes);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP5-0004")]
    [Requirement("REQ-QUIC-RFC9002-SBP5-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryRegisterAcknowledgedPacket_AppliesRecoveryAndCongestionAvoidanceRules()
    {
        foreach (ulong ackedBytes in new ulong[] { 1_200, 2_400, 3_000 })
        {
            QuicCongestionControlState duringRecoveryState = CreateCongestionAvoidanceState(ackedBytes);

            Assert.True(duringRecoveryState.TryRegisterAcknowledgedPacket(
                sentBytes: ackedBytes,
                sentAtMicros: 1_000,
                packetInFlight: true));

            Assert.Equal(12_000UL - ackedBytes, duringRecoveryState.BytesInFlightBytes);
            Assert.Equal(6_000UL, duringRecoveryState.CongestionWindowBytes);
            Assert.Equal(1_000UL, duringRecoveryState.RecoveryStartTimeMicros);

            QuicCongestionControlState afterRecoveryState = CreateCongestionAvoidanceState(ackedBytes);

            Assert.True(afterRecoveryState.TryRegisterAcknowledgedPacket(
                sentBytes: ackedBytes,
                sentAtMicros: 2_000,
                packetInFlight: true));

            ulong expectedGrowthBytes = (1_200UL * ackedBytes) / 6_000UL;
            Assert.Equal(12_000UL - ackedBytes, afterRecoveryState.BytesInFlightBytes);
            Assert.Equal(6_000UL + expectedGrowthBytes, afterRecoveryState.CongestionWindowBytes);
            Assert.Null(afterRecoveryState.RecoveryStartTimeMicros);
        }
    }

    private static QuicCongestionControlState CreateCongestionAvoidanceState(ulong lossBytes)
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(lossBytes, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: lossBytes,
            sentAtMicros: 1_000,
            packetInFlight: true));
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(6_000UL, state.SlowStartThresholdBytes);

        return state;
    }
}

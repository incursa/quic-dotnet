// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S7_3_S7_5_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S7-3-2-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewLossOrEcnDuringRecoveryDoesNotChangeCongestionWindow()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong recoveryStartMicros) in new[]
        {
            (1_200UL, 1_000UL),
            (1_472UL, 2_000UL),
            (3_000UL, 3_000UL),
        })
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);
            state.RegisterPacketSent(state.CongestionWindowBytes);

            Assert.True(state.TryRegisterLoss(
                sentBytes: maxDatagramSizeBytes,
                sentAtMicros: recoveryStartMicros,
                packetInFlight: true));

            ulong recoveryWindowBytes = state.CongestionWindowBytes;
            ulong recoveryThresholdBytes = state.SlowStartThresholdBytes;

            Assert.True(state.TryRegisterLoss(
                sentBytes: maxDatagramSizeBytes,
                sentAtMicros: recoveryStartMicros,
                packetInFlight: true));
            Assert.False(state.TryProcessEcn(
                QuicPacketNumberSpace.ApplicationData,
                reportedEcnCeCount: 1,
                largestAcknowledgedPacketSentAtMicros: recoveryStartMicros,
                pathValidated: true));

            Assert.Equal(recoveryStartMicros, state.RecoveryStartTimeMicros);
            Assert.Equal(recoveryWindowBytes, state.CongestionWindowBytes);
            Assert.Equal(recoveryThresholdBytes, state.SlowStartThresholdBytes);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-3-2-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AcknowledgingRecoveryPeriodPacketLeavesRecoveryAndEntersCongestionAvoidance()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong recoveryStartMicros, ulong acknowledgedSentAtMicros) in new[]
        {
            (1_200UL, 1_000UL, 1_001UL),
            (1_472UL, 2_000UL, 2_001UL),
            (3_000UL, 3_000UL, 3_001UL),
        })
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);
            state.RegisterPacketSent(state.CongestionWindowBytes);

            Assert.True(state.TryRegisterLoss(
                sentBytes: maxDatagramSizeBytes,
                sentAtMicros: recoveryStartMicros,
                packetInFlight: true));
            Assert.True(state.HasRecoveryStartTime);

            Assert.True(state.TryRegisterAcknowledgedPacket(
                sentBytes: maxDatagramSizeBytes,
                sentAtMicros: acknowledgedSentAtMicros,
                packetInFlight: true,
                applicationLimited: true));

            Assert.False(state.HasRecoveryStartTime);
            Assert.True(state.IsInCongestionAvoidance);
            Assert.False(state.IsInSlowStart);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-3-3-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CongestionAvoidanceGrowthIsBoundedByAckedWindowAndDatagramSize()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong acknowledgedBytes) in new[]
        {
            (1_200UL, 1_200UL),
            (1_200UL, 6_000UL),
            (1_472UL, 1_472UL),
            (3_000UL, 6_000UL),
        })
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);
            state.RegisterPacketSent(state.CongestionWindowBytes);
            state.RegisterPacketSent(acknowledgedBytes);

            Assert.True(state.TryRegisterLoss(
                sentBytes: maxDatagramSizeBytes,
                sentAtMicros: 1_000,
                packetInFlight: true));
            Assert.True(state.TryRegisterAcknowledgedPacket(
                sentBytes: acknowledgedBytes,
                sentAtMicros: 2_000,
                packetInFlight: true,
                applicationLimited: true));

            ulong congestionWindowBeforeAck = state.CongestionWindowBytes;
            Assert.True(state.TryRegisterAcknowledgedPacket(
                sentBytes: acknowledgedBytes,
                sentAtMicros: 3_000,
                packetInFlight: true,
                pacingLimited: true));

            ulong growthBytes = (state.RecoveryMaxDatagramSizeBytes * acknowledgedBytes) / congestionWindowBeforeAck;
            Assert.True(growthBytes <= state.RecoveryMaxDatagramSizeBytes);
            Assert.Equal(congestionWindowBeforeAck + growthBytes, state.CongestionWindowBytes);
            Assert.True(state.IsInCongestionAvoidance);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-4-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UndecryptablePacketLossBeforeKeysCanBeIgnored()
    {
        foreach ((ulong sentBytes, bool keysAvailable, bool sentAfterEarliestAcknowledgedPacket) in new[]
        {
            (1UL, false, true),
            (1_200UL, false, false),
            (2_400UL, true, false),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(sentBytes);

            Assert.False(state.TryRegisterLoss(
                sentBytes,
                sentAtMicros: 100,
                packetInFlight: true,
                packetCanBeDecrypted: false,
                keysAvailable,
                sentAfterEarliestAcknowledgedPacket));

            Assert.False(state.HasRecoveryStartTime);
            Assert.Equal(sentBytes, state.BytesInFlightBytes);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-4-P1-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LaterPacketLossIsNotIgnored()
    {
        foreach ((ulong sentBytes, bool packetCanBeDecrypted, bool keysAvailable) in new[]
        {
            (1UL, true, false),
            (1_200UL, false, true),
            (2_400UL, true, true),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(sentBytes);

            Assert.True(state.TryRegisterLoss(
                sentBytes,
                sentAtMicros: 2_000,
                packetInFlight: true,
                packetCanBeDecrypted,
                keysAvailable,
                sentAfterEarliestAcknowledgedPacket: true));

            Assert.True(state.HasRecoveryStartTime);
            Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
            Assert.Equal(0UL, state.BytesInFlightBytes);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-5-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProbePacketsCanBypassCongestionWindow()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong overfillBytes, ulong probeBytes) in new[]
        {
            (1_200UL, 0UL, 1UL),
            (1_200UL, 1UL, 1_200UL),
            (1_472UL, 512UL, 1_472UL),
            (3_000UL, 3_000UL, 6_000UL),
        })
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);
            state.RegisterPacketSent(state.CongestionWindowBytes + overfillBytes);

            Assert.False(state.CanSend(probeBytes));
            Assert.True(state.CanSend(probeBytes, isProbePacket: true));
        }
    }
}

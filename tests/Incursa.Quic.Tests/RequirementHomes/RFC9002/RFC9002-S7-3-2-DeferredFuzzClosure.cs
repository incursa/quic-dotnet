// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S7_3_2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S7-3-1-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LossOrValidatedEcnCeIncreaseEntersRecovery()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong recoverySentAtMicros) in new[]
        {
            (1_200UL, 1UL),
            (1_472UL, 1_000UL),
            (3_000UL, 50_000UL),
        })
        {
            QuicCongestionControlState lossState = new(maxDatagramSizeBytes);
            ulong initialWindowBytes = lossState.CongestionWindowBytes;
            lossState.RegisterPacketSent(maxDatagramSizeBytes);

            Assert.True(lossState.TryRegisterLoss(
                sentBytes: maxDatagramSizeBytes,
                sentAtMicros: recoverySentAtMicros,
                packetInFlight: true));

            Assert.True(lossState.HasRecoveryStartTime);
            Assert.Equal(recoverySentAtMicros, lossState.RecoveryStartTimeMicros);
            Assert.Equal(
                QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
                    initialWindowBytes,
                    minimumCongestionWindowBytes: lossState.MinimumCongestionWindowBytes),
                lossState.CongestionWindowBytes);

            QuicCongestionControlState ecnState = new(maxDatagramSizeBytes);
            Assert.True(ecnState.TryProcessEcn(
                QuicPacketNumberSpace.ApplicationData,
                reportedEcnCeCount: 1,
                largestAcknowledgedPacketSentAtMicros: recoverySentAtMicros,
                pathValidated: true));

            Assert.True(ecnState.HasRecoveryStartTime);
            Assert.Equal(recoverySentAtMicros, ecnState.RecoveryStartTimeMicros);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-3-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RecoveryEntryCutsSlowStartThresholdToHalfCongestionWindow()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong sentBytes) in new[]
        {
            (1_200UL, 1UL),
            (1_472UL, 1_472UL),
            (3_000UL, 3_000UL),
            (10_000UL, 20_000UL),
        })
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);
            ulong congestionWindowBeforeLoss = state.CongestionWindowBytes;
            state.RegisterPacketSent(sentBytes);

            Assert.True(state.TryRegisterLoss(
                sentBytes,
                sentAtMicros: 2_000,
                packetInFlight: true));

            ulong expectedReducedWindowBytes = QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
                congestionWindowBeforeLoss,
                minimumCongestionWindowBytes: state.MinimumCongestionWindowBytes);
            Assert.Equal(expectedReducedWindowBytes, state.SlowStartThresholdBytes);
            Assert.Equal(expectedReducedWindowBytes, state.CongestionWindowBytes);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-3-2-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ReducedCongestionWindowRemainsInPlaceThroughRecoveryExit()
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
            ulong congestionWindowBeforeLoss = state.CongestionWindowBytes;

            Assert.True(state.TryRegisterLoss(
                sentBytes: maxDatagramSizeBytes,
                sentAtMicros: recoveryStartMicros,
                packetInFlight: true));

            ulong expectedReducedWindowBytes = QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
                congestionWindowBeforeLoss,
                minimumCongestionWindowBytes: state.MinimumCongestionWindowBytes);
            Assert.Equal(expectedReducedWindowBytes, state.CongestionWindowBytes);

            Assert.True(state.TryRegisterAcknowledgedPacket(
                sentBytes: maxDatagramSizeBytes,
                sentAtMicros: acknowledgedSentAtMicros,
                packetInFlight: true,
                applicationLimited: true));

            Assert.False(state.HasRecoveryStartTime);
            Assert.Equal(expectedReducedWindowBytes, state.SlowStartThresholdBytes);
            Assert.Equal(expectedReducedWindowBytes, state.CongestionWindowBytes);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-3-2-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ReducedCongestionWindowAllowsGentlerReductionFactors()
    {
        foreach ((ulong congestionWindowBytes, ulong numerator, ulong denominator, ulong minimumWindowBytes, ulong expectedReducedWindowBytes) in new[]
        {
            (12_000UL, 1UL, 2UL, 2_400UL, 6_000UL),
            (12_000UL, 7UL, 8UL, 2_400UL, 10_500UL),
            (12_001UL, 7UL, 8UL, 2_400UL, 10_500UL),
            (1_000UL, 7UL, 8UL, 2_400UL, 2_400UL),
            (ulong.MaxValue, 1UL, 2UL, 2_400UL, ulong.MaxValue / 2UL),
        })
        {
            Assert.Equal(expectedReducedWindowBytes, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
                congestionWindowBytes,
                numerator,
                denominator,
                minimumWindowBytes));
        }
    }
}

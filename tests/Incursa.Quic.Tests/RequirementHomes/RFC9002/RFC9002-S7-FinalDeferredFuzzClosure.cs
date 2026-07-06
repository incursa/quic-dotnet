// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S7_FinalDeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S7-6-2-P4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PersistentCongestionWaitsForFirstRttSample()
    {
        foreach ((ulong firstRttSampleMicros, bool expectedCallSucceeded, bool expectedPersistentCongestionDetected) in new[]
        {
            (0UL, false, false),
            (1UL, true, true),
            (1_000UL, true, true),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.Equal(expectedCallSucceeded, state.TryDetectPersistentCongestion(
                CreatePersistentCongestionPackets(2_000, 8_000),
                firstRttSampleMicros,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out bool persistentCongestionDetected));

            Assert.Equal(expectedPersistentCongestionDetected, persistentCongestionDetected);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-6-2-P6-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PersistentCongestionCollapsesCongestionWindowToMinimum()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong earliestLostSentAtMicros, ulong latestLostSentAtMicros) in new[]
        {
            (1_200UL, 2_000UL, 8_000UL),
            (1_472UL, 2_000UL, 8_000UL),
            (3_000UL, 10_000UL, 16_000UL),
        })
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);
            state.RegisterPacketSent(12_000);

            Assert.True(state.TryDetectPersistentCongestion(
                CreatePersistentCongestionPackets(earliestLostSentAtMicros, latestLostSentAtMicros, maxDatagramSizeBytes),
                firstRttSampleMicros: 1,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out bool persistentCongestionDetected));

            Assert.True(persistentCongestionDetected);
            Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
            Assert.False(state.HasRecoveryStartTime);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-7-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacingIntervalScalesInFlightPacketsByWindowRttAndPacketSize()
    {
        foreach ((ulong congestionWindowBytes, ulong smoothedRttMicros, ulong packetSizeBytes, ulong expectedPacingIntervalMicros) in new[]
        {
            (10_000UL, 1_000UL, 1_250UL, 100UL),
            (12_000UL, 12_000UL, 1_200UL, 960UL),
            (14_720UL, 10_000UL, 1_472UL, 800UL),
            (6_000UL, 1_000UL, 3_000UL, 400UL),
        })
        {
            Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
                congestionWindowBytes,
                smoothedRttMicros,
                packetSizeBytes,
                ackOnlyPacket: false,
                out ulong pacingIntervalMicros));

            Assert.Equal(expectedPacingIntervalMicros, pacingIntervalMicros);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-8-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NotPacingLimitedUnderutilizedSenderDoesNotIncreaseCongestionWindow()
    {
        foreach (ulong acknowledgedBytes in new[] { 1UL, 64UL, 1_200UL, 2_400UL })
        {
            QuicCongestionControlState state = new();
            ulong congestionWindowBeforeAck = state.CongestionWindowBytes;
            state.RegisterPacketSent(congestionWindowBeforeAck);

            Assert.True(state.TryRegisterAcknowledgedPacket(
                acknowledgedBytes,
                sentAtMicros: 1_000,
                packetInFlight: true,
                pacingLimited: false));

            Assert.Equal(congestionWindowBeforeAck, state.CongestionWindowBytes);
            Assert.True(state.BytesInFlightBytes < state.CongestionWindowBytes);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-8-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacingDelayDoesNotForceApplicationLimitedWindowSuppression()
    {
        foreach (ulong acknowledgedBytes in new[] { 1UL, 64UL, 1_200UL, 2_400UL })
        {
            QuicCongestionControlState pacingLimitedState = new();
            pacingLimitedState.RegisterPacketSent(acknowledgedBytes);
            ulong pacingLimitedWindowBeforeAck = pacingLimitedState.CongestionWindowBytes;

            Assert.True(pacingLimitedState.TryRegisterAcknowledgedPacket(
                acknowledgedBytes,
                sentAtMicros: 1_000,
                packetInFlight: true,
                applicationLimited: false,
                pacingLimited: true));
            Assert.True(pacingLimitedState.CongestionWindowBytes > pacingLimitedWindowBeforeAck);

            QuicCongestionControlState applicationLimitedState = new();
            applicationLimitedState.RegisterPacketSent(acknowledgedBytes);
            ulong applicationLimitedWindowBeforeAck = applicationLimitedState.CongestionWindowBytes;

            Assert.True(applicationLimitedState.TryRegisterAcknowledgedPacket(
                acknowledgedBytes,
                sentAtMicros: 1_000,
                packetInFlight: true,
                applicationLimited: true,
                pacingLimited: true));
            Assert.Equal(applicationLimitedWindowBeforeAck, applicationLimitedState.CongestionWindowBytes);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-8-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DefaultWindowUpdatesRemainExplicitAfterUnderutilization()
    {
        foreach ((bool applicationLimited, bool pacingLimited, bool expectedGrowth) in new[]
        {
            (true, true, false),
            (false, false, false),
            (false, true, true),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(1_200);
            ulong congestionWindowBeforeAck = state.CongestionWindowBytes;

            Assert.True(state.TryRegisterAcknowledgedPacket(
                sentBytes: 1_200,
                sentAtMicros: 1_000,
                packetInFlight: true,
                applicationLimited: applicationLimited,
                pacingLimited: pacingLimited));

            Assert.Equal(expectedGrowth, state.CongestionWindowBytes > congestionWindowBeforeAck);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-P7-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CongestionControlledPacketsRespectBytesInFlightCeiling()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong preloadedBytes, ulong attemptedBytes, bool isProbePacket, bool expectedCanSend) in new[]
        {
            (1_200UL, 0UL, 12_000UL, false, true),
            (1_200UL, 12_000UL, 1UL, false, false),
            (1_200UL, 12_000UL, 1_200UL, true, true),
            (1_472UL, 14_720UL, 1UL, false, false),
            (1_472UL, 14_720UL, 1_472UL, true, true),
        })
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);
            if (preloadedBytes > 0)
            {
                state.RegisterPacketSent(preloadedBytes);
            }

            Assert.Equal(expectedCanSend, state.CanSend(
                attemptedBytes,
                isAckOnlyPacket: false,
                isProbePacket: isProbePacket));
        }
    }

    private static QuicPersistentCongestionPacket[] CreatePersistentCongestionPackets(
        ulong earliestLostSentAtMicros,
        ulong latestLostSentAtMicros,
        ulong sentBytes = 1_200)
    {
        return
        [
            new(QuicPacketNumberSpace.ApplicationData, earliestLostSentAtMicros, sentBytes, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.ApplicationData, latestLostSentAtMicros, sentBytes, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
        ];
    }
}

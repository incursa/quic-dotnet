// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S6_2_S6_3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S6-2-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProbeTimeoutExpirationDoesNotMarkPriorUnacknowledgedPacketsLost()
    {
        foreach ((QuicPacketNumberSpace packetNumberSpace, ulong packetNumber, ulong sentBytes, ulong sentAtMicros) in new[]
        {
            (QuicPacketNumberSpace.Initial, 1UL, 1UL, 0UL),
            (QuicPacketNumberSpace.Handshake, 2UL, 1_200UL, 1_000UL),
            (QuicPacketNumberSpace.ApplicationData, 3UL, 2_400UL, 2_000UL),
        })
        {
            QuicSenderRecoveryRuntime runtime = new(initialRttMicros: 1_000);
            runtime.RecordPacketSent(
                packetNumberSpace,
                packetNumber,
                sentBytes,
                sentAtMicros,
                ackEliciting: true);

            Assert.Equal(1, runtime.PendingSentPacketCount);
            Assert.True(runtime.TryGetSentPacket(packetNumberSpace, packetNumber, out _));

            runtime.RecordProbeTimeoutExpired();

            Assert.Equal(1, runtime.ProbeTimeoutBackoffCount);
            Assert.Equal(1, runtime.PendingSentPacketCount);
            Assert.True(runtime.TryGetSentPacket(packetNumberSpace, packetNumber, out _));

            IReadOnlyList<QuicLostPacket> lostPackets = runtime.DetectLostPackets(
                sentAtMicros + 1,
                out ulong? earliestLossDetectionTimeMicros,
                out _);

            Assert.Empty(lostPackets);
            Assert.Null(earliestLossDetectionTimeMicros);
            Assert.Equal(1, runtime.PendingSentPacketCount);
            Assert.True(runtime.TryGetSentPacket(packetNumberSpace, packetNumber, out _));
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-3-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryResetClearsRecoveryAndCongestionState()
    {
        foreach ((ulong maxDatagramSizeBytes, QuicPacketNumberSpace packetNumberSpace, ulong sentBytes) in new[]
        {
            (1_200UL, QuicPacketNumberSpace.Initial, 1_200UL),
            (1_472UL, QuicPacketNumberSpace.Handshake, 1_472UL),
            (3_000UL, QuicPacketNumberSpace.ApplicationData, 3_000UL),
        })
        {
            const ulong initialRttMicros = 1_000;
            QuicRecoveryController recoveryController = new(initialRttMicros);
            recoveryController.RecordPacketSent(
                packetNumberSpace,
                packetNumber: 1,
                sentAtMicros: 100,
                isAckElicitingPacket: true);
            recoveryController.RecordProbeTimeoutExpired();

            Assert.True(recoveryController.HasAnyAckElicitingPacketsInFlight);
            Assert.Equal(1, recoveryController.ProbeTimeoutBackoffCount);

            QuicCongestionControlState congestion = new(maxDatagramSizeBytes);
            ulong initialCongestionWindowBytes = congestion.CongestionWindowBytes;
            congestion.RegisterPacketSent(sentBytes);
            Assert.True(congestion.TryRegisterLoss(
                sentBytes,
                sentAtMicros: 100,
                packetInFlight: true));
            Assert.True(congestion.HasRecoveryStartTime);
            Assert.True(congestion.CongestionWindowBytes <= initialCongestionWindowBytes);

            recoveryController.Reset();
            congestion.Reset();

            Assert.False(recoveryController.HasAnyAckElicitingPacketsInFlight);
            Assert.Equal(0, recoveryController.ProbeTimeoutBackoffCount);
            Assert.Equal(initialRttMicros, recoveryController.GetRttEstimator(packetNumberSpace).SmoothedRttMicros);
            Assert.Equal(initialCongestionWindowBytes, congestion.CongestionWindowBytes);
            Assert.Equal(0UL, congestion.BytesInFlightBytes);
            Assert.False(congestion.HasRecoveryStartTime);
            Assert.Equal([0UL, 0UL, 0UL], congestion.EcnCeCounters);
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryRoundTripMeasurementComputesElapsedTimeFromFirstInitial()
    {
        foreach ((ulong firstInitialSentAtMicros, ulong retryReceivedAtMicros, bool expectedMeasured, ulong expectedRoundTripMicros) in new[]
        {
            (0UL, 0UL, true, 0UL),
            (1_000UL, 999UL, false, 0UL),
            (1_000UL, 2_750UL, true, 1_750UL),
            (ulong.MaxValue - 1UL, ulong.MaxValue, true, 1UL),
        })
        {
            Assert.Equal(expectedMeasured, QuicRecoveryTiming.TryMeasureRetryRoundTripMicros(
                firstInitialSentAtMicros,
                retryReceivedAtMicros,
                out ulong retryRoundTripMicros));

            Assert.Equal(expectedRoundTripMicros, retryRoundTripMicros);
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-3-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NonZeroRetryRoundTripCanSeedInitialRtt()
    {
        foreach ((ulong firstInitialSentAtMicros, ulong retryReceivedAtMicros) in new[]
        {
            (1_000UL, 1_001UL),
            (1_000UL, 2_750UL),
            (100_000UL, 433_000UL),
            (ulong.MaxValue - 1_000UL, ulong.MaxValue),
        })
        {
            Assert.True(QuicRecoveryTiming.TryMeasureRetryRoundTripMicros(
                firstInitialSentAtMicros,
                retryReceivedAtMicros,
                out ulong retryRoundTripMicros));
            Assert.True(retryRoundTripMicros > 0);

            QuicRttEstimator estimator = new(retryRoundTripMicros);

            Assert.False(estimator.HasRttSample);
            Assert.Equal(retryRoundTripMicros, estimator.InitialRttMicros);
            Assert.Equal(retryRoundTripMicros, estimator.SmoothedRttMicros);
            Assert.Equal(retryRoundTripMicros / 2, estimator.RttVarMicros);
        }
    }
}

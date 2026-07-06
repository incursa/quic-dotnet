// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_StateAccounting_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InFlightLostPacketsAreRemovedFromBytesInFlight()
    {
        foreach ((ulong sentBytes, bool ackEliciting, bool inFlight, ulong expectedBytesInFlight) in new[]
        {
            (1UL, true, true, 11_999UL),
            (64UL, false, true, 11_936UL),
            (1_200UL, true, false, 12_000UL),
            (2_400UL, false, false, 12_000UL),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.True(state.TryDetectPersistentCongestion(
                [
                    new(
                        QuicPacketNumberSpace.ApplicationData,
                        sentAtMicros: 2_000,
                        sentBytes: sentBytes,
                        ackEliciting: ackEliciting,
                        inFlight: inFlight,
                        acknowledged: false,
                        lost: true),
                ],
                firstRttSampleMicros: 1_000,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out bool persistentCongestionDetected));

            Assert.False(persistentCongestionDetected);
            Assert.Equal(expectedBytesInFlight, state.BytesInFlightBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FirstRttSampleInitializesLatestMinimumSmoothedAndVarianceValues()
    {
        foreach ((ulong sentAtMicros, ulong ackReceivedAtMicros, ulong expectedRttMicros) in new[]
        {
            (0UL, 1UL, 1UL),
            (1_000UL, 2_500UL, 1_500UL),
            (40_000UL, 140_000UL, 100_000UL),
            (500_000UL, 1_000_000UL, 500_000UL),
        })
        {
            QuicRttEstimator estimator = new();

            Assert.True(estimator.TryUpdateFromAck(
                sentAtMicros,
                ackReceivedAtMicros,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true));

            Assert.True(estimator.HasRttSample);
            Assert.Equal(expectedRttMicros, estimator.LatestRttMicros);
            Assert.Equal(expectedRttMicros, estimator.MinRttMicros);
            Assert.Equal(expectedRttMicros, estimator.SmoothedRttMicros);
            Assert.Equal(expectedRttMicros / 2, estimator.RttVarMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP4-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LossDetectionHelpersStartFromTheirInitialState()
    {
        QuicRttEstimator rttEstimator = new();
        QuicAckGenerationState ackState = new();

        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, rttEstimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, rttEstimator.RttVarMicros);
        Assert.Equal(0UL, rttEstimator.LatestRttMicros);
        Assert.Equal(0UL, rttEstimator.MinRttMicros);
        Assert.False(rttEstimator.HasRttSample);

        foreach (int ptoCount in new[] { 0, 1, 3 })
        {
            Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
                ptoCount,
                ackElicitingPacketSent: true));
        }

        foreach (QuicPacketNumberSpace packetNumberSpace in new[]
        {
            QuicPacketNumberSpace.Initial,
            QuicPacketNumberSpace.Handshake,
            QuicPacketNumberSpace.ApplicationData,
        })
        {
            Assert.False(ackState.ShouldSendAckImmediately(packetNumberSpace));
            Assert.False(ackState.CanSendAckOnlyPacket(packetNumberSpace, nowMicros: 0, maxAckDelayMicros: 1));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP3-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CongestionControlStateInitializesFromMaxDatagramSize()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong expectedCongestionWindowBytes, ulong expectedMinimumCongestionWindowBytes) in new[]
        {
            (1UL, 12_000UL, 2_400UL),
            (1_200UL, 12_000UL, 2_400UL),
            (1_472UL, 14_720UL, 2_944UL),
            (2_000UL, 14_720UL, 4_000UL),
            (3_000UL, 14_720UL, 6_000UL),
        })
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);

            Assert.Equal(expectedCongestionWindowBytes, state.CongestionWindowBytes);
            Assert.Equal(expectedMinimumCongestionWindowBytes, state.MinimumCongestionWindowBytes);
            Assert.Equal(0UL, state.BytesInFlightBytes);
            Assert.False(state.HasRecoveryStartTime);
            Assert.Null(state.RecoveryStartTimeMicros);
            Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
            Assert.Equal([0UL, 0UL, 0UL], state.EcnCeCounters);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP4-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NonAckPacketsIncreaseBytesInFlightBySentBytes()
    {
        foreach ((ulong preloadedBytes, ulong sentBytes) in new[]
        {
            (0UL, 1UL),
            (1_200UL, 64UL),
            (6_000UL, 1_200UL),
            (12_000UL, 2_400UL),
        })
        {
            QuicCongestionControlState state = new();
            if (preloadedBytes > 0)
            {
                state.RegisterPacketSent(preloadedBytes);
            }

            state.RegisterPacketSent(sentBytes, isAckOnlyPacket: false);

            Assert.Equal(preloadedBytes + sentBytes, state.BytesInFlightBytes);
        }
    }
}

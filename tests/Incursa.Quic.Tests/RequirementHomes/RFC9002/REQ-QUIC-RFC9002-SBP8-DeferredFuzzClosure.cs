// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SBP8_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP8-0001")]
    [Requirement("REQ-QUIC-RFC9002-SBP8-0003")]
    [Requirement("REQ-QUIC-RFC9002-SBP8-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryDetectPersistentCongestion_RemovesLostBytesOnlyAfterRttSampleGate()
    {
        foreach ((ulong firstRttSampleMicros, ulong preSampleSentAtMicros, ulong postSampleSentAtMicros, bool expectedAccepted, ulong expectedBytesInFlight) in new[]
        {
            (0UL, 500UL, 2_000UL, false, 12_000UL),
            (1UL, 0UL, 2_000UL, true, 9_600UL),
            (1_000UL, 1_000UL, 2_000UL, true, 9_600UL),
            (1_000UL, 999UL, 7_000UL, true, 9_600UL),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.Equal(expectedAccepted, state.TryDetectPersistentCongestion(
                [
                    new(
                        QuicPacketNumberSpace.Initial,
                        preSampleSentAtMicros,
                        sentBytes: 1_200,
                        ackEliciting: true,
                        inFlight: true,
                        acknowledged: false,
                        lost: true),
                    new(
                        QuicPacketNumberSpace.ApplicationData,
                        postSampleSentAtMicros,
                        sentBytes: 1_200,
                        ackEliciting: true,
                        inFlight: true,
                        acknowledged: false,
                        lost: true),
                ],
                firstRttSampleMicros,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out bool persistentCongestionDetected));

            Assert.False(persistentCongestionDetected);
            Assert.Equal(expectedBytesInFlight, state.BytesInFlightBytes);
            Assert.Equal(12_000UL, state.CongestionWindowBytes);
            Assert.False(state.HasRecoveryStartTime);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP8-0002")]
    [Requirement("REQ-QUIC-RFC9002-SBP8-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryDetectPersistentCongestion_UsesLatestLossTimeAndCollapsesWindowAtDuration()
    {
        foreach ((ulong earliestLostSentAtMicros, ulong latestLostSentAtMicros, ulong smoothedRttMicros, ulong rttVarMicros, ulong maxAckDelayMicros, bool expectedPersistentCongestion) in new[]
        {
            (2_000UL, 7_999UL, 1_000UL, 0UL, 0UL, false),
            (2_000UL, 8_000UL, 1_000UL, 0UL, 0UL, true),
            (2_000UL, 8_600UL, 1_200UL, 50UL, 0UL, true),
            (2_000UL, 8_599UL, 1_200UL, 50UL, 0UL, false),
        })
        {
            QuicCongestionControlState recoveryState = CreateStateWithBytesInFlight();

            Assert.True(recoveryState.TryDetectPersistentCongestion(
                CreateLostPackets(earliestLostSentAtMicros, latestLostSentAtMicros),
                firstRttSampleMicros: 1_000,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros,
                out bool recoveryPersistentCongestionDetected,
                applyReset: false));

            Assert.Equal(expectedPersistentCongestion, recoveryPersistentCongestionDetected);
            Assert.Equal(9_600UL, recoveryState.BytesInFlightBytes);
            if (expectedPersistentCongestion)
            {
                Assert.Equal(latestLostSentAtMicros, recoveryState.RecoveryStartTimeMicros);
                Assert.Equal(6_000UL, recoveryState.CongestionWindowBytes);
            }
            else
            {
                Assert.False(recoveryState.HasRecoveryStartTime);
                Assert.Equal(12_000UL, recoveryState.CongestionWindowBytes);
            }

            QuicCongestionControlState collapseState = CreateStateWithBytesInFlight();

            Assert.True(collapseState.TryDetectPersistentCongestion(
                CreateLostPackets(earliestLostSentAtMicros, latestLostSentAtMicros),
                firstRttSampleMicros: 1_000,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros,
                out bool collapsePersistentCongestionDetected));

            Assert.Equal(expectedPersistentCongestion, collapsePersistentCongestionDetected);
            Assert.Equal(9_600UL, collapseState.BytesInFlightBytes);
            if (expectedPersistentCongestion)
            {
                Assert.Equal(collapseState.MinimumCongestionWindowBytes, collapseState.CongestionWindowBytes);
                Assert.Null(collapseState.RecoveryStartTimeMicros);
            }
            else
            {
                Assert.Equal(12_000UL, collapseState.CongestionWindowBytes);
                Assert.False(collapseState.HasRecoveryStartTime);
            }
        }
    }

    private static QuicCongestionControlState CreateStateWithBytesInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        return state;
    }

    private static QuicPersistentCongestionPacket[] CreateLostPackets(
        ulong earliestLostSentAtMicros,
        ulong latestLostSentAtMicros) =>
        [
            new(
                QuicPacketNumberSpace.Initial,
                earliestLostSentAtMicros,
                sentBytes: 1_200,
                ackEliciting: true,
                inFlight: true,
                acknowledged: false,
                lost: true),
            new(
                QuicPacketNumberSpace.ApplicationData,
                latestLostSentAtMicros,
                sentBytes: 1_200,
                ackEliciting: true,
                inFlight: true,
                acknowledged: false,
                lost: true),
        ];
}

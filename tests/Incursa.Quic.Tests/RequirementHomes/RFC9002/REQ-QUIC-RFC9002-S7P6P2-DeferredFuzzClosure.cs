// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S7P6P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PersistentCongestionConsidersLostPacketsAcrossPacketNumberSpaces()
    {
        foreach ((QuicPacketNumberSpace firstSpace, QuicPacketNumberSpace secondSpace, ulong firstLostAtMicros, ulong secondLostAtMicros) in new[]
        {
            (QuicPacketNumberSpace.Initial, QuicPacketNumberSpace.ApplicationData, 2_000UL, 8_000UL),
            (QuicPacketNumberSpace.Handshake, QuicPacketNumberSpace.ApplicationData, 3_000UL, 9_000UL),
            (QuicPacketNumberSpace.ApplicationData, QuicPacketNumberSpace.Initial, 4_000UL, 10_000UL),
            (QuicPacketNumberSpace.ApplicationData, QuicPacketNumberSpace.Handshake, 5_000UL, 11_000UL),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.True(state.TryDetectPersistentCongestion(
                [
                    new(firstSpace, firstLostAtMicros, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                    new(secondSpace, secondLostAtMicros, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                ],
                firstRttSampleMicros: 1_000,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out bool persistentCongestionDetected));

            Assert.True(persistentCongestionDetected);
            Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
            Assert.Null(state.RecoveryStartTimeMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SingleSpaceStateCanDrivePersistentCongestionEvaluation()
    {
        foreach ((ulong secondLostAtMicros, bool expectedPersistentCongestion) in new[]
        {
            (6_999UL, false),
            (7_000UL, false),
            (8_000UL, true),
            (12_000UL, true),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.True(state.TryDetectPersistentCongestion(
                [
                    new(QuicPacketNumberSpace.ApplicationData, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                    new(QuicPacketNumberSpace.ApplicationData, secondLostAtMicros, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                ],
                firstRttSampleMicros: 1_000,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out bool persistentCongestionDetected));

            Assert.Equal(expectedPersistentCongestion, persistentCongestionDetected);
            if (expectedPersistentCongestion)
            {
                Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
                Assert.Null(state.RecoveryStartTimeMicros);
            }
            else
            {
                Assert.Equal(12_000UL, state.CongestionWindowBytes);
                Assert.False(state.HasRecoveryStartTime);
            }
        }
    }
}

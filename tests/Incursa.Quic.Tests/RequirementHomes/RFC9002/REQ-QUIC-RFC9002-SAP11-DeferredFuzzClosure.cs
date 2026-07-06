// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP11_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP11-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DiscardedInitialAndHandshakePacketsUpdateLossDetectionState()
    {
        foreach ((ulong initialSentAtMicros, ulong handshakeSentAtMicros, bool expectedPersistentCongestion) in new[]
        {
            (1_000UL, 2_000UL, false),
            (2_000UL, 7_999UL, false),
            (2_000UL, 8_000UL, true),
            (3_000UL, 10_000UL, true),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.True(state.TryDetectPersistentCongestion(
                [
                    new(QuicPacketNumberSpace.Initial, initialSentAtMicros, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                    new(QuicPacketNumberSpace.Handshake, handshakeSentAtMicros, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                ],
                firstRttSampleMicros: 1_000,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out bool persistentCongestionDetected));

            Assert.Equal(expectedPersistentCongestion, persistentCongestionDetected);
            Assert.Equal(9_600UL, state.BytesInFlightBytes);
            if (expectedPersistentCongestion)
            {
                Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
                Assert.False(state.HasRecoveryStartTime);
            }
            else
            {
                Assert.Equal(12_000UL, state.CongestionWindowBytes);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP11-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DiscardedPacketsAreRemovedFromBytesInFlightOnlyWhenTrackedInFlight()
    {
        foreach ((bool initialInFlight, bool handshakeInFlight, ulong expectedBytesInFlight) in new[]
        {
            (false, false, 12_000UL),
            (true, false, 10_800UL),
            (false, true, 10_800UL),
            (true, true, 9_600UL),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.True(state.TryDetectPersistentCongestion(
                [
                    new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: initialInFlight, acknowledged: false, lost: true),
                    new(QuicPacketNumberSpace.Handshake, 8_000, 1_200, ackEliciting: true, inFlight: handshakeInFlight, acknowledged: false, lost: true),
                ],
                firstRttSampleMicros: 1_000,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out _,
                applyReset: false));

            Assert.Equal(expectedBytesInFlight, state.BytesInFlightBytes);
        }
    }
}

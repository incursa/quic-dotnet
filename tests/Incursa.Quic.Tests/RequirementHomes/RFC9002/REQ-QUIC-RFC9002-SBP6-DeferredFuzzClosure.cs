// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SBP6_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP6-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewCongestionEventsEnterRecoveryAndReduceCongestionWindow()
    {
        foreach ((ulong sentBytes, ulong lossSentAtMicros, bool packetInFlight, bool expectedLossAccepted) in new[]
        {
            (1UL, 1_000UL, true, true),
            (1_200UL, 2_000UL, true, true),
            (2_400UL, 3_000UL, true, true),
            (1_200UL, 4_000UL, false, false),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.Equal(expectedLossAccepted, state.TryRegisterLoss(
                sentBytes,
                lossSentAtMicros,
                packetInFlight));

            if (expectedLossAccepted)
            {
                Assert.Equal(lossSentAtMicros, state.RecoveryStartTimeMicros);
                Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
                Assert.Equal(6_000UL, state.CongestionWindowBytes);
                Assert.Equal(12_000UL - sentBytes, state.BytesInFlightBytes);
            }
            else
            {
                Assert.False(state.HasRecoveryStartTime);
                Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
                Assert.Equal(12_000UL, state.CongestionWindowBytes);
                Assert.Equal(12_000UL, state.BytesInFlightBytes);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP6-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RecoveryProbeCanBeSentWhenNormalSendIsBlockedByCongestionWindow()
    {
        foreach (ulong probeBytes in new[] { 1UL, 64UL, 1_200UL, 2_400UL })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(state.CongestionWindowBytes);

            Assert.True(state.TryRegisterLoss(
                sentBytes: 1_200,
                sentAtMicros: 2_000,
                packetInFlight: true));

            Assert.False(state.CanSend(probeBytes));
            Assert.True(state.CanSend(probeBytes, isProbePacket: true));

            ulong beforeProbeBytesInFlight = state.BytesInFlightBytes;
            state.RegisterPacketSent(probeBytes, isProbePacket: true);

            Assert.Equal(beforeProbeBytesInFlight + probeBytes, state.BytesInFlightBytes);
            Assert.Equal(6_000UL, state.CongestionWindowBytes);
        }
    }
}

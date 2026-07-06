// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SBP2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckOnlyPacketsNeverIncreaseBytesInFlight()
    {
        foreach ((ulong sentBytes, ulong preloadedBytes) in new[]
        {
            (0UL, 0UL),
            (1UL, 0UL),
            (64UL, 1_200UL),
            (1_200UL, 6_000UL),
            (12_000UL, 12_000UL),
        })
        {
            QuicCongestionControlState state = new();
            if (preloadedBytes > 0)
            {
                state.RegisterPacketSent(preloadedBytes, isAckOnlyPacket: false);
            }

            ulong beforeAckOnlyBytesInFlight = state.BytesInFlightBytes;

            state.RegisterPacketSent(sentBytes, isAckOnlyPacket: true);

            Assert.Equal(beforeAckOnlyBytesInFlight, state.BytesInFlightBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP2-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EcnCeCountersTrackHighestReportedValueIndependentlyPerPacketNumberSpace()
    {
        QuicCongestionControlState state = new();

        ulong sentAtMicros = 1_000;
        foreach ((QuicPacketNumberSpace packetNumberSpace, ulong reportedEcnCeCount, ulong expectedInitial, ulong expectedHandshake, ulong expectedApplicationData) in new[]
        {
            (QuicPacketNumberSpace.Initial, 3UL, 3UL, 0UL, 0UL),
            (QuicPacketNumberSpace.Handshake, 5UL, 3UL, 5UL, 0UL),
            (QuicPacketNumberSpace.ApplicationData, 7UL, 3UL, 5UL, 7UL),
            (QuicPacketNumberSpace.Initial, 2UL, 3UL, 5UL, 7UL),
            (QuicPacketNumberSpace.Handshake, 9UL, 3UL, 9UL, 7UL),
            (QuicPacketNumberSpace.ApplicationData, 7UL, 3UL, 9UL, 7UL),
            (QuicPacketNumberSpace.Initial, ulong.MaxValue, ulong.MaxValue, 9UL, 7UL),
        })
        {
            Assert.False(state.TryProcessEcn(
                packetNumberSpace,
                reportedEcnCeCount,
                largestAcknowledgedPacketSentAtMicros: sentAtMicros++,
                pathValidated: false));

            Assert.Equal([expectedInitial, expectedHandshake, expectedApplicationData], state.EcnCeCounters);
        }
    }
}

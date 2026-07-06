// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP10_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP10-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LossDeclarationRequiresKnownOlderInFlightUnacknowledgedPackets()
    {
        foreach ((ulong packetNumber, ulong largestAcknowledgedPacketNumber) in new[]
        {
            (0UL, 1UL),
            (7UL, 8UL),
            (100UL, 150UL),
        })
        {
            Assert.True(QuicRecoveryTiming.CanDeclarePacketLost(
                packetAcknowledged: false,
                packetInFlight: true,
                packetNumber,
                largestAcknowledgedPacketNumber));
            Assert.False(QuicRecoveryTiming.CanDeclarePacketLost(
                packetAcknowledged: true,
                packetInFlight: true,
                packetNumber,
                largestAcknowledgedPacketNumber));
            Assert.False(QuicRecoveryTiming.CanDeclarePacketLost(
                packetAcknowledged: false,
                packetInFlight: false,
                packetNumber,
                largestAcknowledgedPacketNumber));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP10-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LossDetectionRemovesLostPacketsAndSchedulesFutureLossMarking()
    {
        foreach ((ulong sentAtMicros, ulong nowMicros, ulong latestRttMicros, ulong smoothedRttMicros) in new[]
        {
            (1_000UL, 2_000UL, 800UL, 1_000UL),
            (5_000UL, 5_100UL, 1UL, 1UL),
            (10_000UL, 11_000UL, 400UL, 1_200UL),
        })
        {
            Assert.True(QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
                sentAtMicros,
                nowMicros,
                latestRttMicros,
                smoothedRttMicros,
                out ulong remainingLossDelayMicros));
            Assert.True(remainingLossDelayMicros <= QuicRecoveryTiming.ComputeLossDelayMicros(
                latestRttMicros,
                smoothedRttMicros));
        }

        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 1_000,
            AckEliciting: true,
            Retransmittable: true));

        Assert.True(runtime.SentPackets.ContainsKey(new QuicConnectionSentPacketKey(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7)));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            handshakeConfirmed: true,
            scheduleRetransmission: true));

        Assert.False(runtime.SentPackets.ContainsKey(new QuicConnectionSentPacketKey(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7)));
        Assert.True(runtime.TryDequeueRetransmission(
            QuicPacketNumberSpace.ApplicationData,
            out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(7UL, retransmission.PacketNumber);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP10-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LossDetectionIgnoresPacketsBeyondTheLargestAcknowledgedBoundary()
    {
        foreach ((ulong largestAcknowledgedPacketNumber, ulong candidatePacketNumber) in new[]
        {
            (0UL, 0UL),
            (9UL, 10UL),
            (100UL, 101UL),
            (ulong.MaxValue - 1, ulong.MaxValue),
        })
        {
            Assert.False(QuicRecoveryTiming.CanDeclarePacketLost(
                packetAcknowledged: false,
                packetInFlight: true,
                candidatePacketNumber,
                largestAcknowledgedPacketNumber));
        }
    }
}

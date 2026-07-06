// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP7_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP7-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryBuildAckFrame_TracksLargestAcknowledgedPacketPerSpaceAcrossArrivals()
    {
        foreach ((QuicPacketNumberSpace space, ulong firstPacket, ulong secondPacket, ulong thirdPacket) in new[]
        {
            (QuicPacketNumberSpace.Initial, 0UL, 3UL, 1UL),
            (QuicPacketNumberSpace.Handshake, 7UL, 2UL, 9UL),
            (QuicPacketNumberSpace.ApplicationData, 12UL, 20UL, 14UL),
        })
        {
            QuicAckGenerationState tracker = new();

            tracker.RecordProcessedPacket(space, firstPacket, ackEliciting: true, receivedAtMicros: 1_000);
            tracker.RecordProcessedPacket(space, secondPacket, ackEliciting: true, receivedAtMicros: 1_100);
            tracker.RecordProcessedPacket(space, thirdPacket, ackEliciting: false, receivedAtMicros: 1_200);

            Assert.True(tracker.TryBuildAckFrame(space, nowMicros: 1_300, out QuicAckFrame frame));
            Assert.Equal(Math.Max(Math.Max(firstPacket, secondPacket), thirdPacket), frame.LargestAcknowledged);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP7-0002")]
    [Requirement("REQ-QUIC-RFC9002-SAP7-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckLossAndEcnProcessing_RemovePacketsAndAdvanceCongestionState()
    {
        foreach ((ulong retainedBytes, ulong lostBytes, ulong ackedBytes, ulong lostSentAtMicros, ulong ackedSentAtMicros, ulong ecnSentAtMicros, QuicPacketNumberSpace ecnSpace) in new[]
        {
            (12_000UL, 1_200UL, 1_200UL, 2_000UL, 3_000UL, 3_500UL, QuicPacketNumberSpace.ApplicationData),
            (10_800UL, 2_400UL, 1_200UL, 2_500UL, 3_200UL, 3_700UL, QuicPacketNumberSpace.Handshake),
            (9_600UL, 3_600UL, 2_400UL, 3_000UL, 4_000UL, 4_500UL, QuicPacketNumberSpace.Initial),
        })
        {
            QuicCongestionControlState state = new();

            state.RegisterPacketSent(retainedBytes);
            state.RegisterPacketSent(lostBytes, isProbePacket: true);

            Assert.True(state.TryRegisterLoss(
                sentBytes: lostBytes,
                sentAtMicros: lostSentAtMicros,
                packetInFlight: true));

            Assert.Equal(retainedBytes, state.BytesInFlightBytes);
            Assert.Equal(lostSentAtMicros, state.RecoveryStartTimeMicros);
            Assert.Equal(6_000UL, state.CongestionWindowBytes);

            Assert.True(state.TryRegisterAcknowledgedPacket(
                sentBytes: ackedBytes,
                sentAtMicros: ackedSentAtMicros,
                packetInFlight: true));

            Assert.Equal(retainedBytes - ackedBytes, state.BytesInFlightBytes);
            Assert.Null(state.RecoveryStartTimeMicros);

            Assert.False(state.TryRegisterAcknowledgedPacket(
                sentBytes: ackedBytes,
                sentAtMicros: ackedSentAtMicros + 1,
                packetInFlight: false));

            Assert.Equal(retainedBytes - ackedBytes, state.BytesInFlightBytes);

            Assert.True(state.TryProcessEcn(
                ecnSpace,
                reportedEcnCeCount: 1,
                largestAcknowledgedPacketSentAtMicros: ecnSentAtMicros,
                pathValidated: true));

            Assert.Equal(ecnSentAtMicros, state.RecoveryStartTimeMicros);
            Assert.Equal(1UL, state.EcnCeCounters[(int)ecnSpace]);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP7-0003")]
    [Requirement("REQ-QUIC-RFC9002-SAP7-0007")]
    [Requirement("REQ-QUIC-RFC9002-SAP7-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryUpdateFromAck_SeedsAndUpdatesRttOnlyForAcceptedAckElicitingSamples()
    {
        foreach ((ulong firstRawRttMicros, ulong secondRawRttMicros, ulong ackDelayMicros, ulong peerMaxAckDelayMicros, bool handshakeConfirmed) in new[]
        {
            (0UL, 500UL, 100UL, 100UL, true),
            (800UL, 1_200UL, 250UL, 200UL, true),
            (1_000UL, 1_500UL, 700UL, 300UL, true),
            (1_400UL, 900UL, 300UL, 100UL, false),
        })
        {
            QuicRttEstimator estimator = new();

            Assert.False(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: 10_000,
                ackReceivedAtMicros: 10_000 + firstRawRttMicros,
                largestAcknowledgedPacketNewlyAcknowledged: false,
                newlyAcknowledgedAckElicitingPacket: true));
            Assert.False(estimator.HasRttSample);

            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: 10_000,
                ackReceivedAtMicros: 10_000 + firstRawRttMicros,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true));

            Assert.Equal(firstRawRttMicros, estimator.LatestRttMicros);
            Assert.Equal(firstRawRttMicros, estimator.MinRttMicros);
            Assert.Equal(firstRawRttMicros, estimator.SmoothedRttMicros);
            Assert.Equal(firstRawRttMicros / 2, estimator.RttVarMicros);

            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: 20_000,
                ackReceivedAtMicros: 20_000 + secondRawRttMicros,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true,
                ackDelayMicros: ackDelayMicros,
                handshakeConfirmed: handshakeConfirmed,
                peerMaxAckDelayMicros: peerMaxAckDelayMicros));

            ulong effectiveAckDelayMicros = handshakeConfirmed
                ? Math.Min(ackDelayMicros, peerMaxAckDelayMicros)
                : ackDelayMicros;
            ulong adjustedRttMicros = secondRawRttMicros >= firstRawRttMicros
                && secondRawRttMicros - firstRawRttMicros >= effectiveAckDelayMicros
                ? secondRawRttMicros - effectiveAckDelayMicros
                : secondRawRttMicros;
            ulong rttDeviationMicros = firstRawRttMicros >= adjustedRttMicros
                ? firstRawRttMicros - adjustedRttMicros
                : adjustedRttMicros - firstRawRttMicros;

            Assert.Equal(secondRawRttMicros, estimator.LatestRttMicros);
            Assert.Equal(Math.Min(firstRawRttMicros, secondRawRttMicros), estimator.MinRttMicros);
            Assert.Equal((7 * firstRawRttMicros + adjustedRttMicros) / 8, estimator.SmoothedRttMicros);
            Assert.Equal((3 * (firstRawRttMicros / 2) + rttDeviationMicros) / 4, estimator.RttVarMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP7-0005")]
    [Requirement("REQ-QUIC-RFC9002-SAP7-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProbeBackoffAndLossTimerSelection_UseResetBackoffAndRecoveryTimers()
    {
        foreach ((ulong probeTimeoutMicros, int ptoCount, ulong? lossTimeMicros, bool antiAmplificationBlocked, bool noAckElicitingPackets, bool peerAddressValidationComplete) in new[]
        {
            (1UL, 0, (ulong?)0UL, false, false, false),
            (2_500UL, 1, null, false, false, false),
            (4_000UL, 2, (ulong?)3_000UL, false, false, false),
            (8_000UL, 3, null, false, true, false),
            ((ulong.MaxValue / 2) + 1, 1, null, true, false, false),
        })
        {
            ulong backedOffPtoMicros = QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
                probeTimeoutMicros,
                ptoCount);

            Assert.Equal(probeTimeoutMicros, QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
                probeTimeoutMicros,
                ptoCount: 0));
            Assert.True(backedOffPtoMicros >= probeTimeoutMicros);

            bool timerSelected = QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
                lossTimeMicros,
                backedOffPtoMicros,
                antiAmplificationBlocked,
                noAckElicitingPackets,
                peerAddressValidationComplete,
                out ulong selectedTimerMicros);

            bool expectedTimerSelected = !antiAmplificationBlocked
                && !(noAckElicitingPackets && peerAddressValidationComplete);
            Assert.Equal(expectedTimerSelected, timerSelected);
            if (expectedTimerSelected)
            {
                Assert.Equal(lossTimeMicros ?? backedOffPtoMicros, selectedTimerMicros);
            }
        }
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckTrackerIndexesPacketsByNumberAndPacketNumberSpace()
    {
        AssertAckTrackerIndexesPacketsByNumberAndPacketNumberSpace();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckTrackerStoresPerPacketRecoveryFields()
    {
        AssertAckTrackerStoresPerPacketRecoveryFields();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LostPacketStateCanBeRetainedForReordering()
    {
        AssertLostPacketStateCanBeRetainedForReordering();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SentPacketsRemainSeparatedByPacketNumberSpace()
    {
        AssertSentPacketsRemainSeparatedByPacketNumberSpace();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckProcessingAppliesToOnlyOnePacketNumberSpace()
    {
        AssertAckProcessingAppliesToOnlyOnePacketNumberSpace();
    }

    private static void AssertAckTrackerIndexesPacketsByNumberAndPacketNumberSpace()
    {
        QuicAckGenerationState tracker = new();

        foreach ((QuicPacketNumberSpace packetNumberSpace, ulong packetNumber, bool ackEliciting, ulong receivedAtMicros) in new[]
        {
            (QuicPacketNumberSpace.Initial, 7UL, false, 1_000UL),
            (QuicPacketNumberSpace.Handshake, 7UL, true, 1_100UL),
            (QuicPacketNumberSpace.ApplicationData, 7UL, false, 1_200UL),
            (QuicPacketNumberSpace.Initial, 42UL, true, 1_300UL),
            (QuicPacketNumberSpace.ApplicationData, 42UL, true, 1_400UL),
        })
        {
            tracker.RecordProcessedPacket(
                packetNumberSpace,
                packetNumber,
                ackEliciting,
                receivedAtMicros);
        }

        AssertAckFrame(tracker, QuicPacketNumberSpace.Initial, expectedLargestAcknowledged: 42);
        AssertAckFrame(tracker, QuicPacketNumberSpace.Handshake, expectedLargestAcknowledged: 7);
        AssertAckFrame(tracker, QuicPacketNumberSpace.ApplicationData, expectedLargestAcknowledged: 42);
    }

    private static void AssertAckTrackerStoresPerPacketRecoveryFields()
    {
        foreach ((ulong packetNumber, ulong receivedAtMicros, QuicEcnCounts ecnCounts) in new[]
        {
            (8UL, 1_000UL, new QuicEcnCounts(1, 0, 0)),
            (9UL, 2_500UL, new QuicEcnCounts(3, 5, 8)),
            (10UL, 65_535UL, new QuicEcnCounts(11, 13, 17)),
        })
        {
            QuicAckGenerationState tracker = new();
            tracker.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros,
                congestionExperienced: ecnCounts.EcnCeCount > 0,
                ecnCounts: ecnCounts);

            Assert.True(tracker.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: receivedAtMicros + 2_000,
                out QuicAckFrame frame));

            Assert.Equal((byte)0x03, frame.FrameType);
            Assert.Equal(packetNumber, frame.LargestAcknowledged);
            Assert.Equal(2_000UL, frame.AckDelay);
            Assert.NotNull(frame.EcnCounts);
            Assert.Equal(ecnCounts.Ect0Count, frame.EcnCounts!.Value.Ect0Count);
            Assert.Equal(ecnCounts.Ect1Count, frame.EcnCounts!.Value.Ect1Count);
            Assert.Equal(ecnCounts.EcnCeCount, frame.EcnCounts!.Value.EcnCeCount);
        }
    }

    private static void AssertLostPacketStateCanBeRetainedForReordering()
    {
        foreach ((ulong reorderedAckSentAtMicros, ulong latestLostSentAtMicros) in new[]
        {
            (5_000UL, 8_000UL),
            (7_000UL, 8_000UL),
            (8_500UL, 9_000UL),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.True(state.TryDetectPersistentCongestion(
                [
                    new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                    new(QuicPacketNumberSpace.Handshake, reorderedAckSentAtMicros, 1_200, ackEliciting: true, inFlight: true, acknowledged: true, lost: false),
                    new(QuicPacketNumberSpace.ApplicationData, latestLostSentAtMicros, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                ],
                firstRttSampleMicros: 1_000,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out bool persistentCongestionDetected));

            Assert.False(persistentCongestionDetected);
            Assert.True(state.HasRecoveryStartTime);
            Assert.Equal(latestLostSentAtMicros, state.RecoveryStartTimeMicros);
            Assert.Equal(6_000UL, state.CongestionWindowBytes);
            Assert.Equal(9_600UL, state.BytesInFlightBytes);
        }
    }

    private static void AssertSentPacketsRemainSeparatedByPacketNumberSpace()
    {
        QuicEcnValidationState state = new();

        foreach ((QuicPacketNumberSpace packetNumberSpace, QuicEcnMarking marking) in new[]
        {
            (QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0),
            (QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0),
            (QuicPacketNumberSpace.Handshake, QuicEcnMarking.Ect1),
            (QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0),
            (QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect1),
            (QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.NotEct),
        })
        {
            state.RecordPacketSent(packetNumberSpace, marking);
        }

        AssertEcnCountsValidate(state, QuicPacketNumberSpace.Initial, new QuicEcnCounts(2, 0, 0), ect0: 2, ect1: 0);
        AssertEcnCountsValidate(state, QuicPacketNumberSpace.Handshake, new QuicEcnCounts(0, 1, 0), ect0: 0, ect1: 1);
        AssertEcnCountsValidate(state, QuicPacketNumberSpace.ApplicationData, new QuicEcnCounts(1, 1, 0), ect0: 1, ect1: 1);
    }

    private static void AssertAckProcessingAppliesToOnlyOnePacketNumberSpace()
    {
        QuicEcnValidationState state = new();
        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Handshake, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect1);

        AssertEcnCountsValidate(state, QuicPacketNumberSpace.Handshake, new QuicEcnCounts(1, 0, 0), ect0: 1, ect1: 0);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: false,
            out bool validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);

        AssertEcnCountsValidate(state, QuicPacketNumberSpace.Initial, new QuicEcnCounts(1, 0, 0), ect0: 1, ect1: 0);
    }

    private static void AssertAckFrame(
        QuicAckGenerationState tracker,
        QuicPacketNumberSpace packetNumberSpace,
        ulong expectedLargestAcknowledged)
    {
        Assert.True(tracker.TryBuildAckFrame(packetNumberSpace, nowMicros: 2_000, out QuicAckFrame frame));
        Assert.Equal(expectedLargestAcknowledged, frame.LargestAcknowledged);
    }

    private static void AssertEcnCountsValidate(
        QuicEcnValidationState state,
        QuicPacketNumberSpace packetNumberSpace,
        QuicEcnCounts reportedCounts,
        ulong ect0,
        ulong ect1)
    {
        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            packetNumberSpace,
            reportedCounts,
            newlyAcknowledgedEct0Packets: ect0,
            newlyAcknowledgedEct1Packets: ect1,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);
    }
}

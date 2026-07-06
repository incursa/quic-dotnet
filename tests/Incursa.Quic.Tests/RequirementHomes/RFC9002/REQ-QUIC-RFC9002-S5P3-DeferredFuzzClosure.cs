// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S5P3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0005")]
    [Requirement("RFC9002-S5-3-P12-S1-R01")]
    [Requirement("RFC9002-S5-3-P12-S2-R01")]
    [Requirement("RFC9002-S5-3-P15-S1-R01")]
    [Requirement("RFC9002-S5-3-P15-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConstructorResetAndFirstSample_SeedEstimatorAcrossRttValues()
    {
        foreach ((ulong initialRttMicros, ulong firstSentAtMicros, ulong firstAckAtMicros) in new[]
        {
            (1UL, 10UL, 10UL),
            (2UL, 10UL, 11UL),
            (333_000UL, 1_000UL, 2_000UL),
            (1_000_000UL, 2_000UL, 3_500UL),
            (uint.MaxValue, 3_000UL, 7_000UL),
        })
        {
            QuicRttEstimator estimator = new(initialRttMicros);

            Assert.False(estimator.HasRttSample);
            Assert.Equal(initialRttMicros, estimator.InitialRttMicros);
            Assert.Equal(initialRttMicros, estimator.SmoothedRttMicros);
            Assert.Equal(initialRttMicros / 2, estimator.RttVarMicros);

            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: firstSentAtMicros,
                ackReceivedAtMicros: firstAckAtMicros,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true));

            ulong firstSampleMicros = firstAckAtMicros - firstSentAtMicros;
            Assert.True(estimator.HasRttSample);
            Assert.Equal(firstSampleMicros, estimator.LatestRttMicros);
            Assert.Equal(firstSampleMicros, estimator.MinRttMicros);
            Assert.Equal(firstSampleMicros, estimator.SmoothedRttMicros);
            Assert.Equal(firstSampleMicros / 2, estimator.RttVarMicros);

            estimator.Reset();

            Assert.False(estimator.HasRttSample);
            Assert.Equal(0UL, estimator.LatestRttMicros);
            Assert.Equal(0UL, estimator.MinRttMicros);
            Assert.Equal(initialRttMicros, estimator.SmoothedRttMicros);
            Assert.Equal(initialRttMicros / 2, estimator.RttVarMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0004")]
    [Requirement("RFC9002-S5-3-P13-S1-R01")]
    [Requirement("RFC9002-S5-3-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryUpdateFromAck_UpdatesAdjustedSubsequentSamplesAcrossDelayBoundaries()
    {
        foreach ((ulong sentAtMicros, ulong ackAtMicros, ulong ackDelayMicros, bool handshakeConfirmed, ulong peerMaxAckDelayMicros, ulong localProcessingDelayMicros, ulong expectedSmoothedRttMicros, ulong expectedRttVarMicros) in new[]
        {
            (500UL, 2_100UL, 400UL, true, 400UL, 0UL, 1_025UL, 425UL),
            (500UL, 2_000UL, 100UL, false, 0UL, 200UL, 1_025UL, 425UL),
            (500UL, 2_000UL, 700UL, false, 0UL, 0UL, 1_062UL, 500UL),
            (500UL, 2_000UL, 500UL, false, 0UL, 0UL, 1_000UL, 375UL),
            (500UL, 2_100UL, 900UL, true, 300UL, 0UL, 1_037UL, 450UL),
        })
        {
            QuicRttEstimator estimator = CreatePrimedEstimator();

            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: sentAtMicros,
                ackReceivedAtMicros: ackAtMicros,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true,
                ackDelayMicros: ackDelayMicros,
                handshakeConfirmed: handshakeConfirmed,
                peerMaxAckDelayMicros: peerMaxAckDelayMicros,
                localProcessingDelayMicros: localProcessingDelayMicros));

            Assert.True(estimator.HasRttSample);
            Assert.Equal(ackAtMicros - sentAtMicros, estimator.LatestRttMicros);
            Assert.Equal(1_000UL, estimator.MinRttMicros);
            Assert.Equal(expectedSmoothedRttMicros, estimator.SmoothedRttMicros);
            Assert.Equal(expectedRttVarMicros, estimator.RttVarMicros);
        }
    }

    private static QuicRttEstimator CreatePrimedEstimator()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        return estimator;
    }
}

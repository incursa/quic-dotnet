// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S5P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0004")]
    [Requirement("RFC9002-S5-2-P2-S1-R01")]
    [Requirement("RFC9002-S5-2-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryUpdateFromAck_MaintainsMinRttFromLocalLatestRttSamples()
    {
        foreach ((ulong firstSentAt, ulong firstAckAt, ulong secondSentAt, ulong secondAckAt, ulong ackDelay) in new[]
        {
            (500UL, 2_000UL, 1_400UL, 3_000UL, 900UL),
            (1_000UL, 2_000UL, 1_100UL, 2_000UL, 300UL),
            (2_000UL, 2_000UL, 2_100UL, 3_600UL, 1_000UL),
            (3_000UL, 4_500UL, 3_800UL, 4_900UL, 500UL),
        })
        {
            QuicRttEstimator estimator = new();

            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: firstSentAt,
                ackReceivedAtMicros: firstAckAt,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true,
                ackDelayMicros: ackDelay,
                handshakeConfirmed: true,
                peerMaxAckDelayMicros: ackDelay));

            ulong firstLatestRtt = firstAckAt - firstSentAt;
            Assert.Equal(firstLatestRtt, estimator.LatestRttMicros);
            Assert.Equal(firstLatestRtt, estimator.MinRttMicros);

            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: secondSentAt,
                ackReceivedAtMicros: secondAckAt,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true,
                ackDelayMicros: ackDelay,
                handshakeConfirmed: true,
                peerMaxAckDelayMicros: ackDelay));

            ulong secondLatestRtt = secondAckAt - secondSentAt;
            Assert.Equal(secondLatestRtt, estimator.LatestRttMicros);
            Assert.Equal(Math.Min(firstLatestRtt, secondLatestRtt), estimator.MinRttMicros);
            Assert.True(estimator.HasRttSample);
        }
    }

    [Fact]
    [Requirement("RFC9002-S5-2-P5-S1-R01")]
    [Requirement("RFC9002-S5-2-P6-S1-R01")]
    [Requirement("RFC9002-S5-2-P6-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RefreshMinRttFromLatestSample_ReestablishesMinRttWithoutChangingRttHistory()
    {
        foreach (ulong refreshedMinRtt in new ulong[] { 800, 1_000, 1_800, 2_400 })
        {
            QuicRttEstimator estimator = new();

            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: 0,
                ackReceivedAtMicros: 1_000,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true));
            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: 1_000,
                ackReceivedAtMicros: 2_600,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true));

            ulong latestRtt = estimator.LatestRttMicros;
            ulong smoothedRtt = estimator.SmoothedRttMicros;
            ulong rttVar = estimator.RttVarMicros;

            estimator.RefreshMinRttFromLatestSample(refreshedMinRtt);

            Assert.Equal(refreshedMinRtt, estimator.MinRttMicros);
            Assert.Equal(latestRtt, estimator.LatestRttMicros);
            Assert.Equal(smoothedRtt, estimator.SmoothedRttMicros);
            Assert.Equal(rttVar, estimator.RttVarMicros);
            Assert.True(estimator.HasRttSample);

            estimator.RefreshMinRttFromLatestSample(refreshedMinRtt);
            Assert.Equal(refreshedMinRtt, estimator.MinRttMicros);
            Assert.Equal(latestRtt, estimator.LatestRttMicros);
            Assert.Equal(smoothedRtt, estimator.SmoothedRttMicros);
            Assert.Equal(rttVar, estimator.RttVarMicros);
        }
    }
}

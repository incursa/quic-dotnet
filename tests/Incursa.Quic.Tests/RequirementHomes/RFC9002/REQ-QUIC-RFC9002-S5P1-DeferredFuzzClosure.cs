// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S5P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryUpdateFromAck_GatesAndComputesRttSamplesAcrossAckProgressSignals()
    {
        foreach ((bool largestNewlyAcknowledged, bool ackElicitingProgress, ulong sentAt, ulong ackAt, bool expectedAccepted) in new[]
        {
            (true, true, 1_200UL, 2_700UL, true),
            (false, true, 1_300UL, 2_900UL, false),
            (true, false, 1_400UL, 3_100UL, false),
            (false, false, 1_500UL, 3_300UL, false),
            (true, true, 2_000UL, 2_000UL, true),
        })
        {
            QuicRttEstimator estimator = new();
            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: 0,
                ackReceivedAtMicros: 1_000,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true));

            ulong previousLatestRtt = estimator.LatestRttMicros;
            ulong previousMinRtt = estimator.MinRttMicros;
            ulong previousSmoothedRtt = estimator.SmoothedRttMicros;
            ulong previousRttVar = estimator.RttVarMicros;

            Assert.Equal(
                expectedAccepted,
                estimator.TryUpdateFromAck(
                    largestAcknowledgedPacketSentAtMicros: sentAt,
                    ackReceivedAtMicros: ackAt,
                    largestAcknowledgedPacketNewlyAcknowledged: largestNewlyAcknowledged,
                    newlyAcknowledgedAckElicitingPacket: ackElicitingProgress));

            if (expectedAccepted)
            {
                Assert.Equal(ackAt - sentAt, estimator.LatestRttMicros);
                continue;
            }

            Assert.Equal(previousLatestRtt, estimator.LatestRttMicros);
            Assert.Equal(previousMinRtt, estimator.MinRttMicros);
            Assert.Equal(previousSmoothedRtt, estimator.SmoothedRttMicros);
            Assert.Equal(previousRttVar, estimator.RttVarMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RecordAcknowledgment_UsesOnlyLargestAcknowledgedPacketForRttSamples()
    {
        foreach ((ulong packetBase, ulong firstSentAt, ulong secondSentAt, ulong largestSentAt, ulong ackAt) in new[]
        {
            (10UL, 1_000UL, 1_900UL, 1_300UL, 2_500UL),
            (20UL, 2_000UL, 2_100UL, 2_450UL, 2_900UL),
            (30UL, 3_500UL, 3_300UL, 3_750UL, 4_500UL),
        })
        {
            QuicRecoveryController controller = new();

            controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetBase, firstSentAt);
            controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetBase + 1, secondSentAt);
            controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetBase + 2, largestSentAt);

            Assert.True(controller.RecordAcknowledgment(
                QuicPacketNumberSpace.ApplicationData,
                largestAcknowledgedPacketNumber: packetBase + 2,
                ackReceivedAtMicros: ackAt,
                newlyAcknowledgedAckElicitingPacketNumbers: [packetBase, packetBase + 2, packetBase + 1]));

            QuicRttEstimator estimator = controller.GetRttEstimator(QuicPacketNumberSpace.ApplicationData);
            ulong expectedLatestRtt = ackAt - largestSentAt;
            Assert.True(estimator.HasRttSample);
            Assert.Equal(expectedLatestRtt, estimator.LatestRttMicros);

            Assert.False(controller.RecordAcknowledgment(
                QuicPacketNumberSpace.ApplicationData,
                largestAcknowledgedPacketNumber: packetBase + 1,
                ackReceivedAtMicros: ackAt + 500,
                newlyAcknowledgedAckElicitingPacketNumbers: [packetBase, packetBase + 1]));
            Assert.Equal(expectedLatestRtt, estimator.LatestRttMicros);
        }
    }
}

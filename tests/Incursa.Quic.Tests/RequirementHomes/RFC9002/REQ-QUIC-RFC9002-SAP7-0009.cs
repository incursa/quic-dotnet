namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP7-0009">On later RTT samples, the endpoint MUST use `latest_rtt - ack_delay` when `latest_rtt` is at least `min_rtt + ack_delay`, otherwise use `latest_rtt`, and then update `rttvar` and `smoothed_rtt` using the weighted averages in the appendix pseudocode.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP7-0009")]
public sealed class REQ_QUIC_RFC9002_SAP7_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryUpdateFromAck_UsesTheAdjustedRttWhenTheSampleExceedsTheAckDelayFloor()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 300,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 300));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_025UL, estimator.SmoothedRttMicros);
        Assert.Equal(425UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryUpdateFromAck_DoesNotSubtractAckDelayWhenTheSampleDoesNotClearTheFloor()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 700,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 500,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 500));

        Assert.Equal(1_300UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_037UL, estimator.SmoothedRttMicros);
        Assert.Equal(450UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryUpdateFromAck_SubtractsAckDelayAtTheBoundary()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 500,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 500));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(375UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryUpdateFromAck_FuzzesAdjustedRttAndWeightedAverageUpdates()
    {
        for (uint sampleIndex = 0; sampleIndex < 128; sampleIndex++)
        {
            ulong firstRawRttMicros = 600 + (sampleIndex * 37 % 900);
            ulong laterRawRttMicros = 700 + (sampleIndex * 53 % 1_100);
            ulong ackDelayMicros = sampleIndex * 29 % 700;
            ulong peerMaxAckDelayMicros = 100 + (sampleIndex * 31 % 500);
            ulong effectiveAckDelayMicros = Math.Min(ackDelayMicros, peerMaxAckDelayMicros);

            QuicRttEstimator estimator = new();
            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: 0,
                ackReceivedAtMicros: firstRawRttMicros,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true));

            ulong secondAckReceivedAtMicros = 10_000 + sampleIndex;
            Assert.True(estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: secondAckReceivedAtMicros - laterRawRttMicros,
                ackReceivedAtMicros: secondAckReceivedAtMicros,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true,
                ackDelayMicros: ackDelayMicros,
                handshakeConfirmed: true,
                peerMaxAckDelayMicros: peerMaxAckDelayMicros));

            ulong adjustedRttMicros = laterRawRttMicros >= firstRawRttMicros
                && laterRawRttMicros - firstRawRttMicros >= effectiveAckDelayMicros
                ? laterRawRttMicros - effectiveAckDelayMicros
                : laterRawRttMicros;
            ulong rttDeviationMicros = firstRawRttMicros >= adjustedRttMicros
                ? firstRawRttMicros - adjustedRttMicros
                : adjustedRttMicros - firstRawRttMicros;

            Assert.Equal(laterRawRttMicros, estimator.LatestRttMicros);
            Assert.Equal(Math.Min(firstRawRttMicros, laterRawRttMicros), estimator.MinRttMicros);
            Assert.Equal((7 * firstRawRttMicros + adjustedRttMicros) / 8, estimator.SmoothedRttMicros);
            Assert.Equal((3 * (firstRawRttMicros / 2) + rttDeviationMicros) / 4, estimator.RttVarMicros);
        }
    }
}

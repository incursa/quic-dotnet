namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0004">An endpoint MUST NOT adjust min_rtt for acknowledgment delays reported by the peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P2-0004")]
public sealed class REQ_QUIC_RFC9002_S5P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryUpdateFromAck_IgnoresPeerAckDelayWhenMaintainingMinRtt()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_400,
            ackReceivedAtMicros: 3_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 900,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 200));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_600UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_050UL, estimator.SmoothedRttMicros);
        Assert.Equal(475UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryUpdateFromAck_DoesNotReduceMinRttUsingPeerAckDelayOnASmallerSample()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_900,
            ackReceivedAtMicros: 3_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 500,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 200));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_100UL, estimator.LatestRttMicros);
        Assert.Equal(1_100UL, estimator.MinRttMicros);
        Assert.Equal(1_450UL, estimator.SmoothedRttMicros);
        Assert.Equal(662UL, estimator.RttVarMicros);
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0003">An endpoint MUST use only locally observed times when computing min_rtt.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P2-0003")]
public sealed class REQ_QUIC_RFC9002_S5P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryUpdateFromAck_SeedsMinRttFromTheLocalObservationEvenWhenPeerDelayFieldsArePresent()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 900,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 200,
            localProcessingDelayMicros: 200));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_500UL, estimator.MinRttMicros);
        Assert.Equal(1_500UL, estimator.SmoothedRttMicros);
        Assert.Equal(750UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryUpdateFromAck_DoesNotUsePeerAckDelayWhenUpdatingMinRttOnLaterSamples()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 100,
            handshakeConfirmed: false,
            localProcessingDelayMicros: 200));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_025UL, estimator.SmoothedRttMicros);
        Assert.Equal(425UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryUpdateFromAck_LeavesMinRttAtTheLocalBoundaryWhenLocalDelayConsumesTheSlack()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 800,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 100,
            handshakeConfirmed: false,
            localProcessingDelayMicros: 200));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_200UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(375UL, estimator.RttVarMicros);
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

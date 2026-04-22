namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5-0001">An endpoint MUST compute min_rtt, smoothed_rtt, and rttvar for each path.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5-0001")]
public sealed class REQ_QUIC_RFC9002_S5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryUpdateFromAck_ComputesTheInitialRttSampleAndDerivedValues()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_500UL, estimator.MinRttMicros);
        Assert.Equal(1_500UL, estimator.SmoothedRttMicros);
        Assert.Equal(750UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordAcknowledgment_AppliesTheSamePathRttSampleAcrossPacketNumberSpaces()
    {
        QuicRecoveryController controller = new();

        controller.RecordPacketSent(QuicPacketNumberSpace.Initial, packetNumber: 1, sentAtMicros: 100_000);
        controller.RecordPacketSent(QuicPacketNumberSpace.Handshake, packetNumber: 2, sentAtMicros: 100_000);
        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 3, sentAtMicros: 100_000);

        Assert.True(controller.RecordAcknowledgment(
            QuicPacketNumberSpace.Initial,
            largestAcknowledgedPacketNumber: 1,
            ackReceivedAtMicros: 140_000,
            newlyAcknowledgedAckElicitingPacketNumbers: new ulong[] { 1 },
            isInitialPacket: true,
            ignoreAckDelayForInitialPacket: true));

        QuicRttEstimator initialEstimator = controller.GetRttEstimator(QuicPacketNumberSpace.Initial);
        QuicRttEstimator handshakeEstimator = controller.GetRttEstimator(QuicPacketNumberSpace.Handshake);
        QuicRttEstimator applicationEstimator = controller.GetRttEstimator(QuicPacketNumberSpace.ApplicationData);

        Assert.True(initialEstimator.HasRttSample);
        Assert.True(handshakeEstimator.HasRttSample);
        Assert.True(applicationEstimator.HasRttSample);

        Assert.Equal(40_000UL, initialEstimator.LatestRttMicros);
        Assert.Equal(initialEstimator.LatestRttMicros, handshakeEstimator.LatestRttMicros);
        Assert.Equal(initialEstimator.LatestRttMicros, applicationEstimator.LatestRttMicros);
        Assert.Equal(initialEstimator.SmoothedRttMicros, handshakeEstimator.SmoothedRttMicros);
        Assert.Equal(initialEstimator.SmoothedRttMicros, applicationEstimator.SmoothedRttMicros);
        Assert.Equal(initialEstimator.RttVarMicros, handshakeEstimator.RttVarMicros);
        Assert.Equal(initialEstimator.RttVarMicros, applicationEstimator.RttVarMicros);
    }
}

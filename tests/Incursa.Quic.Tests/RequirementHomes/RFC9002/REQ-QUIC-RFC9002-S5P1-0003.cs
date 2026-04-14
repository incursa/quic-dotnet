namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P1-0003">An RTT sample MUST use only the largest acknowledged packet in the received ACK frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P1-0003")]
public sealed class REQ_QUIC_RFC9002_S5P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordAcknowledgment_UsesOnlyTheLargestAcknowledgedPacketSendTimeWhenMultiplePacketsAreNewlyAcknowledged()
    {
        QuicRecoveryController controller = new();

        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 7, sentAtMicros: 1_000);
        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 8, sentAtMicros: 1_900);
        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 1_300);

        Assert.True(controller.RecordAcknowledgment(
            QuicPacketNumberSpace.ApplicationData,
            largestAcknowledgedPacketNumber: 9,
            ackReceivedAtMicros: 2_500,
            newlyAcknowledgedAckElicitingPacketNumbers: new ulong[] { 7, 9, 8 }));

        Assert.False(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));

        QuicRttEstimator estimator = controller.GetRttEstimator(QuicPacketNumberSpace.ApplicationData);
        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_200UL, estimator.LatestRttMicros);
        Assert.Equal(1_200UL, estimator.MinRttMicros);
        Assert.Equal(1_200UL, estimator.SmoothedRttMicros);
        Assert.Equal(600UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordAcknowledgment_DoesNotUpdateTheRttWhenALaterAckOnlyAdvancesSmallerPackets()
    {
        QuicRecoveryController controller = new();

        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 7, sentAtMicros: 1_000);
        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 8, sentAtMicros: 1_900);
        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 1_300);

        Assert.True(controller.RecordAcknowledgment(
            QuicPacketNumberSpace.ApplicationData,
            largestAcknowledgedPacketNumber: 9,
            ackReceivedAtMicros: 2_500,
            newlyAcknowledgedAckElicitingPacketNumbers: new ulong[] { 7, 9, 8 }));

        QuicRttEstimator estimator = controller.GetRttEstimator(QuicPacketNumberSpace.ApplicationData);
        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_200UL, estimator.LatestRttMicros);
        Assert.Equal(1_200UL, estimator.MinRttMicros);
        Assert.Equal(1_200UL, estimator.SmoothedRttMicros);
        Assert.Equal(600UL, estimator.RttVarMicros);

        Assert.False(controller.RecordAcknowledgment(
            QuicPacketNumberSpace.ApplicationData,
            largestAcknowledgedPacketNumber: 8,
            ackReceivedAtMicros: 3_000,
            newlyAcknowledgedAckElicitingPacketNumbers: new ulong[] { 7, 8 }));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_200UL, estimator.LatestRttMicros);
        Assert.Equal(1_200UL, estimator.MinRttMicros);
        Assert.Equal(1_200UL, estimator.SmoothedRttMicros);
        Assert.Equal(600UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void RecordAcknowledgment_UsesTheLargestAcknowledgedPacketTimeAtTheZeroBoundary()
    {
        QuicRecoveryController controller = new();

        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 7, sentAtMicros: 1_000);
        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 8, sentAtMicros: 1_200);
        controller.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 1_300);

        Assert.True(controller.RecordAcknowledgment(
            QuicPacketNumberSpace.ApplicationData,
            largestAcknowledgedPacketNumber: 9,
            ackReceivedAtMicros: 1_300,
            newlyAcknowledgedAckElicitingPacketNumbers: new ulong[] { 7, 9, 8 }));

        Assert.False(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));

        QuicRttEstimator estimator = controller.GetRttEstimator(QuicPacketNumberSpace.ApplicationData);
        Assert.True(estimator.HasRttSample);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(0UL, estimator.SmoothedRttMicros);
        Assert.Equal(0UL, estimator.RttVarMicros);
    }
}

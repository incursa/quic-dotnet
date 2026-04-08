namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0006">Before any RTT samples are available for a new path, or when the estimator is reset, the RTT estimator MUST be initialized using the initial RTT.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P3-0006")]
public sealed class REQ_QUIC_RFC9002_S5P3_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ConstructorAndReset_SeedTheEstimatorWithTheConfiguredInitialRtt()
    {
        QuicRttEstimator estimator = new();

        Assert.False(estimator.HasRttSample);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.InitialRttMicros);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, estimator.RttVarMicros);

        QuicRttEstimator resumedEstimator = new(initialRttMicros: 123_000);

        Assert.False(resumedEstimator.HasRttSample);
        Assert.Equal(123_000UL, resumedEstimator.InitialRttMicros);
        Assert.Equal(0UL, resumedEstimator.LatestRttMicros);
        Assert.Equal(0UL, resumedEstimator.MinRttMicros);
        Assert.Equal(123_000UL, resumedEstimator.SmoothedRttMicros);
        Assert.Equal(61_500UL, resumedEstimator.RttVarMicros);

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 1_900,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        estimator.Reset();

        Assert.False(estimator.HasRttSample);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryUpdateFromAck_DoesNotReinitializeAPrimedEstimatorToTheInitialRtt()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_500,
            ackReceivedAtMicros: 3_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_062UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void ConstructorAndReset_UseTheSmallestValidInitialRtt()
    {
        QuicRttEstimator estimator = new(initialRttMicros: 1);

        Assert.False(estimator.HasRttSample);
        Assert.Equal(1UL, estimator.InitialRttMicros);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(1UL, estimator.SmoothedRttMicros);
        Assert.Equal(0UL, estimator.RttVarMicros);

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        estimator.Reset();

        Assert.False(estimator.HasRttSample);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(1UL, estimator.SmoothedRttMicros);
        Assert.Equal(0UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void Constructor_RejectsZeroInitialRtt()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicRttEstimator(initialRttMicros: 0));
    }
}

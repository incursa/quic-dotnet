namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2-0001">Resumed connections over the same network MAY use the previous connection&apos;s final smoothed RTT value as the resumed connection&apos;s initial RTT.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P2-0001")]
public sealed class REQ_QUIC_RFC9002_S6P2P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void Constructor_RequiresExplicitReuseOfThePriorFinalSmoothedRtt()
    {
        QuicRttEstimator previousConnectionEstimator = new();

        Assert.True(previousConnectionEstimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));
        Assert.Equal(1_000UL, previousConnectionEstimator.SmoothedRttMicros);

        QuicRttEstimator resumedConnectionEstimator = new();

        Assert.NotEqual(previousConnectionEstimator.SmoothedRttMicros, resumedConnectionEstimator.InitialRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, resumedConnectionEstimator.InitialRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, resumedConnectionEstimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, resumedConnectionEstimator.RttVarMicros);
        Assert.False(resumedConnectionEstimator.HasRttSample);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void Constructor_CanReuseTheSmallestObservedPriorFinalSmoothedRtt()
    {
        QuicRttEstimator previousConnectionEstimator = new();

        Assert.True(previousConnectionEstimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));
        Assert.Equal(1UL, previousConnectionEstimator.SmoothedRttMicros);

        QuicRttEstimator resumedConnectionEstimator = new(previousConnectionEstimator.SmoothedRttMicros);

        Assert.Equal(1UL, resumedConnectionEstimator.InitialRttMicros);
        Assert.Equal(0UL, resumedConnectionEstimator.LatestRttMicros);
        Assert.Equal(0UL, resumedConnectionEstimator.MinRttMicros);
        Assert.Equal(1UL, resumedConnectionEstimator.SmoothedRttMicros);
        Assert.Equal(0UL, resumedConnectionEstimator.RttVarMicros);
        Assert.False(resumedConnectionEstimator.HasRttSample);
    }
}

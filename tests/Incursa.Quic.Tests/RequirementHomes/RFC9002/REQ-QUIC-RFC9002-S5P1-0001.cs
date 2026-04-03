namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S5P1-0001")]
public sealed class REQ_QUIC_RFC9002_S5P1_0001
{
    public static TheoryData<RttSampleGateCase> TryUpdateFromAckGateCases => new()
    {
        new(true, true, true, 1_000, 2_500),
        new(false, true, false, 1_000, 2_500),
        new(true, false, false, 1_000, 2_500),
        new(false, false, false, 1_000, 2_500),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0001")]
    [Trait("Category", "Positive")]
    public void TryUpdateFromAck_GeneratesAnRttSampleOnlyForNewAckElicitingPackets()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 400,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 250));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_500UL, estimator.MinRttMicros);
        Assert.Equal(1_500UL, estimator.SmoothedRttMicros);
        Assert.Equal(750UL, estimator.RttVarMicros);

        Assert.False(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_100,
            ackReceivedAtMicros: 2_600,
            largestAcknowledgedPacketNewlyAcknowledged: false,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.False(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_200,
            ackReceivedAtMicros: 2_700,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: false));
    }

    [Theory]
    [MemberData(nameof(TryUpdateFromAckGateCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0001")]
    [Trait("Category", "Property")]
    public void TryUpdateFromAck_GatesSampleCreationAcrossAckProgressBoundaries(RttSampleGateCase scenario)
    {
        QuicRttEstimator estimator = new();

        Assert.Equal(
            scenario.ExpectedAccepted,
            estimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: scenario.LargestAcknowledgedPacketSentAtMicros,
                ackReceivedAtMicros: scenario.AckReceivedAtMicros,
                largestAcknowledgedPacketNewlyAcknowledged: scenario.LargestAcknowledgedPacketNewlyAcknowledged,
                newlyAcknowledgedAckElicitingPacket: scenario.NewlyAcknowledgedAckElicitingPacket));

        if (!scenario.ExpectedAccepted)
        {
            Assert.False(estimator.HasRttSample);
            Assert.Equal(0UL, estimator.LatestRttMicros);
            Assert.Equal(0UL, estimator.MinRttMicros);
            Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
            Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, estimator.RttVarMicros);
            return;
        }

        ulong expectedLatestRttMicros = scenario.AckReceivedAtMicros - scenario.LargestAcknowledgedPacketSentAtMicros;
        Assert.True(estimator.HasRttSample);
        Assert.Equal(expectedLatestRttMicros, estimator.LatestRttMicros);
        Assert.Equal(expectedLatestRttMicros, estimator.MinRttMicros);
        Assert.Equal(expectedLatestRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(expectedLatestRttMicros / 2, estimator.RttVarMicros);
    }

    public sealed record RttSampleGateCase(
        bool LargestAcknowledgedPacketNewlyAcknowledged,
        bool NewlyAcknowledgedAckElicitingPacket,
        bool ExpectedAccepted,
        ulong LargestAcknowledgedPacketSentAtMicros,
        ulong AckReceivedAtMicros);
}

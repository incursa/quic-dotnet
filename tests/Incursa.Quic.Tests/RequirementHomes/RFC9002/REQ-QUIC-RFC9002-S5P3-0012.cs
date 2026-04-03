namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S5P3-0012")]
public sealed class REQ_QUIC_RFC9002_S5P3_0012
{
    public static TheoryData<RttBoundCase> RttBoundCases => new()
    {
        new(500, 1_400, 300, 300, 900, 987, 400),
        new(600, 2_000, 500, 500, 1_000, 1_050, 475),
    };

    [Theory]
    [MemberData(nameof(RttBoundCases))]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Property")]
    public void TryUpdateFromAck_KeepsAdjustedRttBoundedByTheObservedMinRtt(RttBoundCase scenario)
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: scenario.SecondSampleSentAtMicros,
            ackReceivedAtMicros: scenario.SecondSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: scenario.AckDelayMicros,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: scenario.PeerMaxAckDelayMicros));

        Assert.Equal(scenario.ExpectedMinRttMicros, estimator.MinRttMicros);
        Assert.Equal(scenario.ExpectedSmoothedRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(scenario.ExpectedRttVarMicros, estimator.RttVarMicros);
        Assert.True(estimator.LatestRttMicros >= estimator.MinRttMicros);
        Assert.True(estimator.SmoothedRttMicros >= estimator.MinRttMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryUpdateFromAck_KeepsAdjustedRttAtOrAboveObservedMinRttWhenAckDelayWouldOvershoot()
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
            ackDelayMicros: 400,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 400));

        Assert.Equal(1_300UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_037UL, estimator.SmoothedRttMicros);
        Assert.Equal(450UL, estimator.RttVarMicros);
    }

    public sealed record RttBoundCase(
        ulong SecondSampleSentAtMicros,
        ulong SecondSampleAckReceivedAtMicros,
        ulong AckDelayMicros,
        ulong PeerMaxAckDelayMicros,
        ulong ExpectedMinRttMicros,
        ulong ExpectedSmoothedRttMicros,
        ulong ExpectedRttVarMicros);
}

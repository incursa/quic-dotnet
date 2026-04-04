namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0009">After the handshake is confirmed, an endpoint MUST use the lesser of the acknowledgment delay and the peer&apos;s max_ack_delay.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P3-0009")]
public sealed class REQ_QUIC_RFC9002_S5P3_0009
{
    public static TheoryData<RttClampCase> ClampCases => new()
    {
        new(200, 300, 1_037, 450),
        new(300, 300, 1_025, 425),
        new(600, 300, 1_025, 425),
    };

    [Theory]
    [MemberData(nameof(ClampCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryUpdateFromAck_ClampsAckDelayAfterHandshakeConfirmation(RttClampCase scenario)
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
            ackDelayMicros: scenario.AckDelayMicros,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: scenario.PeerMaxAckDelayMicros));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(scenario.ExpectedSmoothedRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(scenario.ExpectedRttVarMicros, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryUpdateFromAck_LeavesAckDelayUnclampedBeforeHandshakeConfirmation()
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
            ackDelayMicros: 600,
            handshakeConfirmed: false,
            peerMaxAckDelayMicros: 300));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_062UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
    }

    public sealed record RttClampCase(
        ulong AckDelayMicros,
        ulong PeerMaxAckDelayMicros,
        ulong ExpectedSmoothedRttMicros,
        ulong ExpectedRttVarMicros);
}

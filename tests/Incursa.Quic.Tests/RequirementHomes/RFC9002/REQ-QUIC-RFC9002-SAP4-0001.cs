namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP4-0001">At the beginning of a connection, the loss detection state MUST be initialized by resetting the loss detection timer, setting pto_count to 0, setting latest_rtt to 0, setting smoothed_rtt to kInitialRtt, setting rttvar to kInitialRtt / 2, setting min_rtt to 0, setting first_rtt_sample to 0, and initializing the per-packet-number-space tracking state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP4-0001")]
public sealed class REQ_QUIC_RFC9002_SAP4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionStart_SeedsTheLossDetectionHelpersWithTheirInitialState()
    {
        QuicCongestionControlState congestionState = new();
        QuicRttEstimator rttEstimator = new();
        QuicAckGenerationState ackState = new();

        Assert.Equal((ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, congestionState.MaxDatagramSizeBytes);
        Assert.Equal(12_000UL, congestionState.CongestionWindowBytes);
        Assert.Equal(2_400UL, congestionState.MinimumCongestionWindowBytes);
        Assert.Equal(0UL, congestionState.BytesInFlightBytes);
        Assert.False(congestionState.HasRecoveryStartTime);

        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, rttEstimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, rttEstimator.RttVarMicros);
        Assert.Equal(0UL, rttEstimator.LatestRttMicros);
        Assert.Equal(0UL, rttEstimator.MinRttMicros);
        Assert.False(rttEstimator.HasRttSample);

        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(ptoCount: 0));
        Assert.False(ackState.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));
        Assert.False(ackState.ShouldSendAckImmediately(QuicPacketNumberSpace.Handshake));
        Assert.False(ackState.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(ackState.CanSendAckOnlyPacket(QuicPacketNumberSpace.Initial, 0, 1));
        Assert.False(ackState.CanSendAckOnlyPacket(QuicPacketNumberSpace.Handshake, 0, 1));
        Assert.False(ackState.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, 0, 1));
    }
}

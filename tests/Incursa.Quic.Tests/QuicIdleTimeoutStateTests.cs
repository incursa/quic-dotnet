namespace Incursa.Quic.Tests;

public sealed class QuicIdleTimeoutStateTests
{
    [Theory]
    [InlineData(25UL, null, 5UL, true, 25UL)]
    [InlineData(0UL, 40UL, 5UL, true, 40UL)]
    [InlineData(25UL, 40UL, 5UL, true, 25UL)]
    [InlineData(4UL, 10UL, 2UL, true, 6UL)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0001">To avoid excessively small idle timeout periods, endpoints MUST increase the idle timeout period to be at least three times the current Probe Timeout (PTO).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0007">Endpoints MUST increase the idle timeout period to be at least three times the current Probe Timeout (PTO).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0003">Each endpoint MUST advertise a `max_idle_timeout`, and the effective value at an endpoint is the minimum of the two advertised values, or the sole advertised value if only one endpoint advertises a non-zero value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S10P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryComputeEffectiveIdleTimeoutMicros_UsesTheMinimumAdvertisedValueAndThePtoFloor(
        ulong? localMaxIdleTimeoutMicros,
        ulong? peerMaxIdleTimeoutMicros,
        ulong currentProbeTimeoutMicros,
        bool expectedComputed,
        ulong expectedEffectiveIdleTimeoutMicros)
    {
        Assert.Equal(expectedComputed, QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros,
            peerMaxIdleTimeoutMicros,
            currentProbeTimeoutMicros,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(expectedEffectiveIdleTimeoutMicros, effectiveIdleTimeoutMicros);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0003">Each endpoint MUST advertise a `max_idle_timeout`, and the effective value at an endpoint is the minimum of the two advertised values, or the sole advertised value if only one endpoint advertises a non-zero value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeEffectiveIdleTimeoutMicros_ReturnsFalseWhenNeitherEndpointAdvertisesAnIdleTimeout()
    {
        Assert.False(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: null,
            peerMaxIdleTimeoutMicros: null,
            currentProbeTimeoutMicros: 5,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(0UL, effectiveIdleTimeoutMicros);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0005">An endpoint MUST restart its idle timer when a packet from its peer is received and processed successfully.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0006">An endpoint MUST also restart its idle timer when it sends an ack-eliciting packet if no other ack-eliciting packets have been sent since it last received and processed a packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S10P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void RecordPeerPacketProcessedAndRecordAckElicitingPacketSent_RestartTheTimerAtTheRightTimes()
    {
        QuicIdleTimeoutState state = new(100);

        Assert.Equal(0UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(100UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        Assert.False(state.HasTimedOut(100));
        Assert.True(state.HasTimedOut(101));

        state.RecordAckElicitingPacketSent(20);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        Assert.False(state.HasTimedOut(120));
        Assert.True(state.HasTimedOut(121));

        state.RecordAckElicitingPacketSent(30);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);

        state.RecordPeerPacketProcessed(40);

        Assert.Equal(40UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(140UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordAckElicitingPacketSent(60);

        Assert.Equal(60UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(160UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }
}

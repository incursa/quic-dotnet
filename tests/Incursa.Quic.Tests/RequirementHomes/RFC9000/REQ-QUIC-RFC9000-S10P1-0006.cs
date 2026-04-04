namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0006">An endpoint MUST also restart its idle timer when it sends an ack-eliciting packet if no other ack-eliciting packets have been sent since it last received and processed a packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P1-0006")]
public sealed class REQ_QUIC_RFC9000_S10P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordAckElicitingPacketSent_RestartsOnlyOnTheFirstSendAfterAPeerPacket()
    {
        QuicIdleTimeoutState state = new(100);

        state.RecordPeerPacketProcessed(20);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordAckElicitingPacketSent(30);

        Assert.Equal(30UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(130UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordAckElicitingPacketSent(40);

        Assert.Equal(30UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(130UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordPeerPacketProcessed(50);
        state.RecordAckElicitingPacketSent(60);

        Assert.Equal(60UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(160UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }
}

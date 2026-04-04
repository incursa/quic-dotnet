namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP5-0002">When a sent packet is in flight and ack-eliciting, the sender MUST update time_of_last_ack_eliciting_packet[pn_space] to now().</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP5-0002")]
public sealed class REQ_QUIC_RFC9002_SAP5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicIdleTimeoutState_TracksTheMostRecentAckElicitingSendTime()
    {
        QuicIdleTimeoutState state = new(100);

        Assert.Equal(0UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(100UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordAckElicitingPacketSent(20);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordPeerPacketProcessed(40);
        state.RecordAckElicitingPacketSent(60);

        Assert.Equal(60UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(160UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void QuicIdleTimeoutState_DoesNotExtendTheDeadlineForRepeatedLocalActivity()
    {
        QuicIdleTimeoutState state = new(100);

        state.RecordAckElicitingPacketSent(20);
        state.RecordAckElicitingPacketSent(30);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordPeerPacketProcessed(40);

        Assert.Equal(40UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(140UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }
}

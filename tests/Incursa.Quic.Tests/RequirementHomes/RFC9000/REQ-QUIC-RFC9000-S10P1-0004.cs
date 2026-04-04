namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0004">An endpoint that announces a max_idle_timeout MUST initiate an immediate close if it abandons the connection before the effective timeout expires.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P1-0004")]
public sealed class REQ_QUIC_RFC9000_S10P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordAckElicitingPacketSent_RestartsTheDeadlineAfterPeerTraffic()
    {
        QuicIdleTimeoutState state = new(100);
        state.RecordPeerPacketProcessed(20);
        state.RecordAckElicitingPacketSent(40);

        Assert.Equal(40UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(140UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        Assert.False(state.HasTimedOut(140));
        Assert.True(state.HasTimedOut(141));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordAckElicitingPacketSent_DoesNotExtendTheDeadlineForRepeatedLocalActivity()
    {
        QuicIdleTimeoutState state = new(100);
        state.RecordAckElicitingPacketSent(20);
        state.RecordAckElicitingPacketSent(30);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecordPeerPacketProcessed_ResetsTheOutgoingActivityWindowAtTheBoundary()
    {
        QuicIdleTimeoutState state = new(100);
        state.RecordAckElicitingPacketSent(20);
        state.RecordPeerPacketProcessed(40);

        Assert.Equal(40UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(140UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        Assert.False(state.HasTimedOut(140));
        Assert.True(state.HasTimedOut(141));
    }
}

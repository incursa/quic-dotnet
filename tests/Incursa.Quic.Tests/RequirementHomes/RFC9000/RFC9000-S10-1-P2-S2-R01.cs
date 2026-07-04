// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S10-1-P2-S2-R01">An endpoint that announces a max_idle_timeout MUST initiate an immediate close if it abandons the connection before the effective timeout expires.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-1-P2-S2-R01")]
public sealed class RFC9000_S10_1_P2_S2_R01
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

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S10-1-P3-S2-R01">An endpoint MUST also restart its idle timer when it sends an ack-eliciting packet if no other ack-eliciting packets have been sent since it last received and processed a packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-1-P3-S2-R01")]
public sealed class RFC9000_S10_1_P3_S2_R01
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

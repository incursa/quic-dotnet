// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0552">An endpoint MUST restart its idle timer when a packet from its peer is received and processed successfully.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0552")]
public sealed class REQ_QUIC_RFC9000_0552
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-0552")]
    public void RecordAckElicitingPacketSent_DoesNotKeepRestartingWithoutSuccessfulPeerProcessing()
    {
        QuicIdleTimeoutState state = new(100);

        state.RecordAckElicitingPacketSent(20);
        state.RecordAckElicitingPacketSent(40);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordPeerPacketProcessed(60);

        Assert.Equal(60UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(160UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordPeerPacketProcessed_RestartsTheIdleTimer()
    {
        QuicIdleTimeoutState state = new(100);

        Assert.Equal(0UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(100UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordPeerPacketProcessed(20);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordPeerPacketProcessed(40);

        Assert.Equal(40UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(140UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }
}

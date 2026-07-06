// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1P2-0002">An implementation of QUIC MAY provide applications with an option to defer an idle timeout.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P1P2-0002")]
public sealed class REQ_QUIC_RFC9000_S10P1P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S5P3-0010")]
    public void RecordAckElicitingPacketSent_AllowsDeferredIdleTimeoutAfterPeerActivity()
    {
        QuicIdleTimeoutState state = new(100);

        state.RecordPeerPacketProcessed(40);

        Assert.Equal(40UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(140UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordAckElicitingPacketSent(60);

        Assert.Equal(60UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(160UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S5P3-0010")]
    public void RecordAckElicitingPacketSent_DoesNotKeepExtendingTheDeadlineForRepeatedLocalTraffic()
    {
        QuicIdleTimeoutState state = new(100);

        state.RecordAckElicitingPacketSent(20);
        state.RecordAckElicitingPacketSent(30);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-S5P3-0010")]
    public void Fuzz_AckElicitingMaintenanceCanDeferIdleTimeoutOnceAfterPeerActivity()
    {
        foreach ((ulong timeoutMicros, ulong peerPacketAt, ulong firstLocalSendAt, ulong secondLocalSendAt) in new[]
        {
            (20UL, 5UL, 8UL, 10UL),
            (100UL, 40UL, 60UL, 70UL),
            (1_000UL, 250UL, 750UL, 900UL),
            (ulong.MaxValue - 10UL, 4UL, 8UL, 9UL),
        })
        {
            QuicIdleTimeoutState state = new(timeoutMicros);

            state.RecordPeerPacketProcessed(peerPacketAt);
            Assert.Equal(peerPacketAt, state.IdleTimerRestartAtMicros);
            Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

            state.RecordAckElicitingPacketSent(firstLocalSendAt);
            ulong expectedDeferredDeadline = SaturatingAdd(firstLocalSendAt, timeoutMicros);

            Assert.Equal(firstLocalSendAt, state.IdleTimerRestartAtMicros);
            Assert.Equal(expectedDeferredDeadline, state.IdleTimeoutDeadlineMicros);
            Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
            Assert.False(state.HasTimedOut(expectedDeferredDeadline));

            state.RecordAckElicitingPacketSent(secondLocalSendAt);

            Assert.Equal(firstLocalSendAt, state.IdleTimerRestartAtMicros);
            Assert.Equal(expectedDeferredDeadline, state.IdleTimeoutDeadlineMicros);
            Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        }
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        return ulong.MaxValue - left < right
            ? ulong.MaxValue
            : left + right;
    }
}

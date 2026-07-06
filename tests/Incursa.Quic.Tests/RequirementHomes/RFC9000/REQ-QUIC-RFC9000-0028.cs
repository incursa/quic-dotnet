// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0028")]
public sealed class REQ_QUIC_RFC9000_0028
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordPeerPacketProcessed_AfterClientActivityRestartsIdleDeadline()
    {
        QuicIdleTimeoutState idle = new(effectiveIdleTimeoutMicros: 100);

        idle.RecordAckElicitingPacketSent(sentAtMicros: 90);
        Assert.Equal(190UL, idle.IdleTimeoutDeadlineMicros);
        Assert.True(idle.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        idle.RecordPeerPacketProcessed(receivedAtMicros: 99);

        Assert.Equal(99UL, idle.IdleTimerRestartAtMicros);
        Assert.Equal(199UL, idle.IdleTimeoutDeadlineMicros);
        Assert.False(idle.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        Assert.False(idle.HasTimedOut(190));
        Assert.False(idle.HasTimedOut(199));
        Assert.True(idle.HasTimedOut(200));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordAckElicitingPacketSent_DoesNotKeepExtendingWithoutPeerActivity()
    {
        QuicIdleTimeoutState idle = new(effectiveIdleTimeoutMicros: 100);

        idle.RecordAckElicitingPacketSent(sentAtMicros: 90);
        idle.RecordAckElicitingPacketSent(sentAtMicros: 95);

        Assert.Equal(90UL, idle.IdleTimerRestartAtMicros);
        Assert.Equal(190UL, idle.IdleTimeoutDeadlineMicros);
        Assert.True(idle.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        Assert.False(idle.HasTimedOut(190));
        Assert.True(idle.HasTimedOut(191));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RecordPeerPacketProcessed_FuzzRestartsIdleDeadlineAfterClientActivity()
    {
        for (ulong timeoutMicros = 25; timeoutMicros <= 125; timeoutMicros += 25)
        {
            ulong sentAtMicros = timeoutMicros - 5;
            ulong receivedAtMicros = timeoutMicros + 3;
            QuicIdleTimeoutState idle = new(effectiveIdleTimeoutMicros: timeoutMicros);

            idle.RecordAckElicitingPacketSent(sentAtMicros);
            idle.RecordPeerPacketProcessed(receivedAtMicros);

            ulong expectedDeadline = receivedAtMicros + timeoutMicros;
            Assert.Equal(receivedAtMicros, idle.IdleTimerRestartAtMicros);
            Assert.Equal(expectedDeadline, idle.IdleTimeoutDeadlineMicros);
            Assert.False(idle.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
            Assert.False(idle.HasTimedOut(expectedDeadline));
            Assert.True(idle.HasTimedOut(expectedDeadline + 1));
        }
    }
}

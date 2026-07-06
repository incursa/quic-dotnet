// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S10_1_IdleTimeout_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P1P2-0002")]
    [Requirement("RFC9000-S10-1-P1-S1-R01")]
    [Requirement("RFC9000-S10-1-P3-S1-R01")]
    [Requirement("RFC9000-S10-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void IdleTimeoutRestartFuzz_PreservesDeadlineAndFirstAckElicitingSendInvariants()
    {
        uint stateSeed = 0x90_00_10_01;

        for (int iteration = 0; iteration < 256; iteration++)
        {
            ulong timeoutMicros = 1UL + (Next(ref stateSeed) % 100_000UL);
            ulong peerReceivedAtMicros = Next(ref stateSeed) % 1_000_000UL;
            ulong firstAckElicitingSentAtMicros = peerReceivedAtMicros + 1UL + (Next(ref stateSeed) % 1_000UL);
            ulong secondAckElicitingSentAtMicros = firstAckElicitingSentAtMicros + 1UL + (Next(ref stateSeed) % 1_000UL);
            ulong nextPeerReceivedAtMicros = secondAckElicitingSentAtMicros + 1UL + (Next(ref stateSeed) % 1_000UL);

            QuicIdleTimeoutState state = new(timeoutMicros);

            state.RecordPeerPacketProcessed(peerReceivedAtMicros);

            Assert.Equal(peerReceivedAtMicros, state.IdleTimerRestartAtMicros);
            Assert.Equal(peerReceivedAtMicros + timeoutMicros, state.IdleTimeoutDeadlineMicros);
            Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
            Assert.False(state.HasTimedOut(peerReceivedAtMicros + timeoutMicros));
            Assert.True(state.HasTimedOut(peerReceivedAtMicros + timeoutMicros + 1UL));

            state.RecordAckElicitingPacketSent(firstAckElicitingSentAtMicros);

            Assert.Equal(firstAckElicitingSentAtMicros, state.IdleTimerRestartAtMicros);
            Assert.Equal(firstAckElicitingSentAtMicros + timeoutMicros, state.IdleTimeoutDeadlineMicros);
            Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
            Assert.False(state.HasTimedOut(firstAckElicitingSentAtMicros + timeoutMicros));
            Assert.True(state.HasTimedOut(firstAckElicitingSentAtMicros + timeoutMicros + 1UL));

            state.RecordAckElicitingPacketSent(secondAckElicitingSentAtMicros);

            Assert.Equal(firstAckElicitingSentAtMicros, state.IdleTimerRestartAtMicros);
            Assert.Equal(firstAckElicitingSentAtMicros + timeoutMicros, state.IdleTimeoutDeadlineMicros);
            Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

            state.RecordPeerPacketProcessed(nextPeerReceivedAtMicros);

            Assert.Equal(nextPeerReceivedAtMicros, state.IdleTimerRestartAtMicros);
            Assert.Equal(nextPeerReceivedAtMicros + timeoutMicros, state.IdleTimeoutDeadlineMicros);
            Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        }
    }

    private static ulong Next(ref uint state)
    {
        state = unchecked((state * 1_664_525U) + 1_013_904_223U);
        return state;
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S5P1P2P6_PeerConnectionIdRetirement_DeferredFuzzClosure
{
    [Theory]
    [InlineData(2UL, 0x20)]
    [InlineData(3UL, 0x40)]
    [InlineData(5UL, 0x60)]
    [Requirement("RFC9000-S5-1-2-P6-S1-R01")]
    [Requirement("RFC9000-S5-1-2-P6-S2-R01")]
    [Requirement("RFC9000-S5-1-2-P6-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PeerConnectionIdRetirementFuzz_TracksTwiceTheActiveLimitAndDoesNotForgetUnretiredIds(
        ulong activeConnectionIdLimit,
        int connectionIdSeed)
    {
        QuicConnectionPeerConnectionIdState state = new();
        ulong pendingLimit = QuicConnectionPeerConnectionIdState.GetPendingRetiredConnectionIdLimit(activeConnectionIdLimit);

        for (ulong sequenceNumber = 1; sequenceNumber <= pendingLimit; sequenceNumber++)
        {
            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                sequenceNumber,
                retirePriorTo: sequenceNumber,
                connectionIdStart: unchecked((byte)(connectionIdSeed + (int)sequenceNumber)),
                activeConnectionIdLimit,
                out QuicTransportErrorCode errorCode,
                out _,
                out ulong[] retiredSequenceNumbers));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.Single(retiredSequenceNumbers);
            Assert.Equal(sequenceNumber - 1, retiredSequenceNumbers[0]);
            Assert.Equal((int)sequenceNumber, state.PendingRetiredConnectionIdCount);
            Assert.Equal(sequenceNumber, state.CurrentDestinationConnectionIdSequence);
        }

        byte[] currentConnectionIdBeforeRejection = state.CurrentDestinationConnectionId.ToArray();
        ulong rejectedSequenceNumber = pendingLimit + 1;
        Assert.False(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            rejectedSequenceNumber,
            retirePriorTo: rejectedSequenceNumber,
            connectionIdStart: unchecked((byte)(connectionIdSeed + (int)rejectedSequenceNumber)),
            activeConnectionIdLimit,
            out QuicTransportErrorCode failureCode,
            out bool destinationConnectionIdChanged,
            out ulong[] rejectedRetiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, failureCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(rejectedRetiredSequenceNumbers);
        Assert.Equal((int)pendingLimit, state.PendingRetiredConnectionIdCount);
        Assert.Equal(pendingLimit, state.CurrentDestinationConnectionIdSequence);
        Assert.Equal(currentConnectionIdBeforeRejection, state.CurrentDestinationConnectionId.ToArray());
    }
}

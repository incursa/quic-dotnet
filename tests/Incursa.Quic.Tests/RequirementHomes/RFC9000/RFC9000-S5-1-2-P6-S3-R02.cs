// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-1-2-P6-S3-R02")]
public sealed class RFC9000_S5_1_2_P6_S3_R02
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerConnectionIdState_TreatsExcessPendingRetirementsAsConnectionIdLimitError()
    {
        QuicConnectionPeerConnectionIdState state = new();
        RetireUpToTheLimit(state);

        Assert.False(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 5UL,
            retirePriorTo: 5UL,
            connectionIdStart: 0xA5,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode errorCode,
            out _,
            out _));

        Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PeerConnectionIdState_DoesNotTreatPendingRetirementsAtTheLimitAsAnError()
    {
        QuicConnectionPeerConnectionIdState state = new();

        RetireUpToTheLimit(state);

        Assert.Equal(4, state.PendingRetiredConnectionIdCount);
        Assert.Equal(4UL, state.CurrentDestinationConnectionIdSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PeerConnectionIdState_AcceptsDuplicateAlreadyRetiredConnectionIdEvenWhenAtTheLimit()
    {
        QuicConnectionPeerConnectionIdState state = new();
        RetireUpToTheLimit(state);

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 2UL,
            retirePriorTo: 2UL,
            connectionIdStart: 0xA2,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode errorCode,
            out _,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(4, state.PendingRetiredConnectionIdCount);
    }

    private static void RetireUpToTheLimit(QuicConnectionPeerConnectionIdState state)
    {
        for (ulong sequenceNumber = 1; sequenceNumber <= 4; sequenceNumber++)
        {
            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                sequenceNumber,
                retirePriorTo: sequenceNumber,
                connectionIdStart: unchecked((byte)(0xA0 + sequenceNumber)),
                activeConnectionIdLimit: 2UL,
                out QuicTransportErrorCode errorCode,
                out _,
                out _));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        }
    }

}

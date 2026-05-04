namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0012")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerConnectionIdState_LimitsPendingRetiredConnectionIdsToTwiceTheActiveLimit()
    {
        QuicConnectionPeerConnectionIdState state = new();

        RetireUpToTheLimit(state, activeConnectionIdLimit: 2UL);

        Assert.Equal(4, state.PendingRetiredConnectionIdCount);
        Assert.Equal(
            4UL,
            QuicConnectionPeerConnectionIdState.GetPendingRetiredConnectionIdLimit(activeConnectionIdLimit: 2UL));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PeerConnectionIdState_RejectsRetirePriorToWhenPendingRetiredConnectionIdsWouldExceedTheLimit()
    {
        QuicConnectionPeerConnectionIdState state = new();
        RetireUpToTheLimit(state, activeConnectionIdLimit: 2UL);

        Assert.False(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 5UL,
            retirePriorTo: 5UL,
            connectionIdStart: 0x25,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode errorCode,
            out _,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, errorCode);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(4, state.PendingRetiredConnectionIdCount);
        Assert.Equal(4UL, state.CurrentDestinationConnectionIdSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PeerConnectionIdState_DuplicateAlreadyRetiredSequenceDoesNotIncreaseThePendingLimit()
    {
        QuicConnectionPeerConnectionIdState state = new();
        RetireUpToTheLimit(state, activeConnectionIdLimit: 2UL);

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 3UL,
            retirePriorTo: 3UL,
            connectionIdStart: 0x23,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(4, state.PendingRetiredConnectionIdCount);
    }

    private static void RetireUpToTheLimit(
        QuicConnectionPeerConnectionIdState state,
        ulong activeConnectionIdLimit)
    {
        for (ulong sequenceNumber = 1; sequenceNumber <= 4; sequenceNumber++)
        {
            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                sequenceNumber,
                retirePriorTo: sequenceNumber,
                connectionIdStart: unchecked((byte)(0x20 + sequenceNumber)),
                activeConnectionIdLimit,
                out QuicTransportErrorCode errorCode,
                out _,
                out _));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        }
    }

}

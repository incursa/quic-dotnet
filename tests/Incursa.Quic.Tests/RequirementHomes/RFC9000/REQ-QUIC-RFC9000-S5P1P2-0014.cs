namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0014")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewConnectionIdFrame_ReturnsEveryRemovedPeerConnectionIdForRetirement()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionIdStart: 0x70,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode errorCode,
            out _,
            out _));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 2UL,
            retirePriorTo: 2UL,
            connectionIdStart: 0x80,
            activeConnectionIdLimit: 2UL,
            out errorCode,
            out _,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Equal([0UL, 1UL], retiredSequenceNumbers.Order().ToArray());
        Assert.Equal(1, state.ActiveConnectionIdCount);
        Assert.Equal(2UL, state.CurrentDestinationConnectionIdSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NewConnectionIdFrame_WhenRetirementReportingWouldExceedTheLimitDoesNotForgetTheCurrentConnectionId()
    {
        QuicConnectionPeerConnectionIdState state = new();

        for (ulong sequenceNumber = 1; sequenceNumber <= 4; sequenceNumber++)
        {
            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                sequenceNumber,
                retirePriorTo: sequenceNumber,
                connectionIdStart: unchecked((byte)(0x80 + sequenceNumber)),
                activeConnectionIdLimit: 2UL,
                out QuicTransportErrorCode errorCode,
                out _,
                out _));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        }

        byte[] currentConnectionIdBeforeRejection = state.CurrentDestinationConnectionId.ToArray();
        Assert.False(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 5UL,
            retirePriorTo: 5UL,
            connectionIdStart: 0x90,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode failureCode,
            out _,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, failureCode);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(1, state.ActiveConnectionIdCount);
        Assert.Equal(4UL, state.CurrentDestinationConnectionIdSequence);
        Assert.Equal(currentConnectionIdBeforeRejection, state.CurrentDestinationConnectionId.ToArray());
    }

}

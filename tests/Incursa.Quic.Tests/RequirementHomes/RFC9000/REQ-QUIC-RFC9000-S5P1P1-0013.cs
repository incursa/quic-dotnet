namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0013")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewConnectionIdMayTemporarilyExceedTheLimitWhenRetirePriorToRemovesTheExcess()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionIdStart: 0x10,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode errorCode,
            out _,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Empty(retiredSequenceNumbers);

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 2UL,
            retirePriorTo: 1UL,
            connectionIdStart: 0x20,
            activeConnectionIdLimit: 2UL,
            out errorCode,
            out bool destinationConnectionIdChanged,
            out retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL], retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NewConnectionIdCannotTemporarilyExceedTheLimitWithoutImmediateRetirement()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionIdStart: 0x30,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode errorCode,
            out _,
            out _));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);

        Assert.False(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 2UL,
            retirePriorTo: 0UL,
            connectionIdStart: 0x40,
            activeConnectionIdLimit: 2UL,
            out errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RetirePriorToCanRetireMultipleExcessConnectionIdsAtOnce()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionIdStart: 0x50,
            activeConnectionIdLimit: 3UL,
            out QuicTransportErrorCode errorCode,
            out _,
            out _));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 2UL,
            retirePriorTo: 2UL,
            connectionIdStart: 0x60,
            activeConnectionIdLimit: 3UL,
            out errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL, 1UL], retiredSequenceNumbers);
        Assert.Equal(1, state.ActiveConnectionIdCount);
    }
}

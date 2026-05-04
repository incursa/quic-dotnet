namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0023")]
public sealed class REQ_QUIC_RFC9000_S19P15_0023
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0023")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryAcceptNewConnectionId_WithSequenceBelowPriorRetirePriorToReportsRetirement()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] activeConnectionId = [0x30, 0x31, 0x32, 0x33];
        byte[] staleConnectionId = [0x10, 0x11, 0x12, 0x13];

        Assert.True(AcceptFrame(
            state,
            sequenceNumber: 0x03,
            retirePriorTo: 0x02,
            activeConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL], retiredSequenceNumbers);

        Assert.True(AcceptFrame(
            state,
            sequenceNumber: 0x01,
            retirePriorTo: 0x00,
            staleConnectionId,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Equal([1UL], retiredSequenceNumbers);
        Assert.Equal(0x03UL, state.CurrentDestinationConnectionIdSequence);
        Assert.True(activeConnectionId.AsSpan().SequenceEqual(state.CurrentDestinationConnectionId.Span));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0023")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryAcceptNewConnectionId_WithSequenceBelowPriorRetirePriorToDoesNotCloseConnection()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(AcceptFrame(
            state,
            sequenceNumber: 0x04,
            retirePriorTo: 0x03,
            connectionId: [0x40, 0x41, 0x42, 0x43],
            out QuicTransportErrorCode errorCode,
            out _,
            out _));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);

        Assert.True(AcceptFrame(
            state,
            sequenceNumber: 0x02,
            retirePriorTo: 0x00,
            connectionId: [0x20, 0x21, 0x22, 0x23],
            out errorCode,
            out _,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Equal([2UL], retiredSequenceNumbers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0023")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryAcceptNewConnectionId_RepeatedStaleSequenceDoesNotReportDuplicateRetirement()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] staleConnectionId = [0x10, 0x11, 0x12, 0x13];

        Assert.True(AcceptFrame(
            state,
            sequenceNumber: 0x03,
            retirePriorTo: 0x02,
            connectionId: [0x30, 0x31, 0x32, 0x33],
            out _,
            out _,
            out _));

        Assert.True(AcceptFrame(
            state,
            sequenceNumber: 0x01,
            retirePriorTo: 0x00,
            staleConnectionId,
            out _,
            out _,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal([1UL], retiredSequenceNumbers);

        Assert.True(AcceptFrame(
            state,
            sequenceNumber: 0x01,
            retirePriorTo: 0x00,
            staleConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
    }

    private static bool AcceptFrame(
        QuicConnectionPeerConnectionIdState state,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        out QuicTransportErrorCode errorCode,
        out bool destinationConnectionIdChanged,
        out ulong[] retiredSequenceNumbers)
    {
        return state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                sequenceNumber,
                retirePriorTo,
                connectionId,
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(unchecked((byte)(0x60 + sequenceNumber)))),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03, 0x04],
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers);
    }
}

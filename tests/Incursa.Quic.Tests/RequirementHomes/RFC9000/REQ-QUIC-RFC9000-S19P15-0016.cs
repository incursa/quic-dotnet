namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0016")]
public sealed class REQ_QUIC_RFC9000_S19P15_0016
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryAcceptNewConnectionId_AllowsAnExactDuplicateFrame()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] statelessResetToken = CreateStatelessResetToken(0x20);
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);

        Assert.True(state.TryAcceptNewConnectionId(
            frame,
            requiresZeroLengthDestinationConnectionId: false,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal(0x06UL, state.CurrentDestinationConnectionIdSequence);
        Assert.True(connectionId.AsSpan().SequenceEqual(state.CurrentDestinationConnectionId.Span));

        Assert.True(state.TryAcceptNewConnectionId(
            frame,
            requiresZeroLengthDestinationConnectionId: false,
            out errorCode,
            out destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Equal(0x06UL, state.CurrentDestinationConnectionIdSequence);
        Assert.True(connectionId.AsSpan().SequenceEqual(state.CurrentDestinationConnectionId.Span));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryAcceptNewConnectionId_RejectsSameSequenceWhenTheFrameIsNotAnExactDuplicate()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] connectionId = [0x20, 0x21, 0x22, 0x23];

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x03, 0x00, connectionId, CreateStatelessResetToken(0x30)),
            requiresZeroLengthDestinationConnectionId: false,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);

        Assert.False(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x03, 0x00, connectionId, CreateStatelessResetToken(0x40)),
            requiresZeroLengthDestinationConnectionId: false,
            out errorCode,
            out destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
        Assert.False(destinationConnectionIdChanged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0016")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryAcceptNewConnectionId_AllowsAnExactDuplicateWhenActiveSetIsAtTheLocalLimit()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] initialConnectionId = [0x01, 0x02, 0x03, 0x04];
        byte[] connectionId = [0x50, 0x51, 0x52, 0x53];
        QuicNewConnectionIdFrame frame = new(0x01, 0x00, connectionId, CreateStatelessResetToken(0x60));

        Assert.True(state.TryAcceptNewConnectionId(
            frame,
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: initialConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);

        Assert.True(state.TryAcceptNewConnectionId(
            frame,
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: initialConnectionId,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);
    }

    private static byte[] CreateStatelessResetToken(byte startValue)
    {
        byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = unchecked((byte)(startValue + index));
        }

        return token;
    }
}

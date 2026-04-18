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

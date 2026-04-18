namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0018")]
public sealed class REQ_QUIC_RFC9000_S19P15_0018
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryAcceptNewConnectionId_RejectsTheSameSequenceNumberForDifferentConnectionIds()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] statelessResetToken = CreateStatelessResetToken(0x30);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x01, 0x00, [0x10, 0x11, 0x12], statelessResetToken),
            requiresZeroLengthDestinationConnectionId: false,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);

        Assert.False(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x01, 0x00, [0x20, 0x21, 0x22], statelessResetToken),
            requiresZeroLengthDestinationConnectionId: false,
            out errorCode,
            out destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
        Assert.False(destinationConnectionIdChanged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryAcceptNewConnectionId_RejectsTheSameConnectionIdWithADifferentSequenceNumberOrToken()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] firstToken = CreateStatelessResetToken(0x40);
        byte[] secondToken = CreateStatelessResetToken(0x50);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x02, 0x01, connectionId, firstToken),
            requiresZeroLengthDestinationConnectionId: false,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);

        Assert.False(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x03, 0x02, connectionId, secondToken),
            requiresZeroLengthDestinationConnectionId: false,
            out errorCode,
            out destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
        Assert.False(destinationConnectionIdChanged);
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

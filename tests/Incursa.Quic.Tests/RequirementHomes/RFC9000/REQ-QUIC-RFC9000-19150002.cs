// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-19150002")]
public sealed class REQ_QUIC_RFC9000_19150002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-19150002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryAcceptNewConnectionId_WhenZeroLengthDestinationConnectionIdIsRequired_ReturnsProtocolViolation()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] connectionId = [0x10, 0x11, 0x12];

        Assert.False(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x02, 0x00, connectionId, CreateStatelessResetToken(0x20)),
            requiresZeroLengthDestinationConnectionId: true,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
        Assert.False(destinationConnectionIdChanged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-19150002")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryAcceptNewConnectionId_RejectsWhenZeroLengthDestinationConnectionIdIsRequired()
    {
        QuicConnectionPeerConnectionIdState state = new();

        QuicNewConnectionIdFrame frame = new(
            0x01,
            0x00,
            [0x10, 0x11, 0x12],
            CreateStatelessResetToken(0x20));

        Assert.False(state.TryAcceptNewConnectionId(
            frame,
            requiresZeroLengthDestinationConnectionId: true,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.True(state.CurrentDestinationConnectionId.IsEmpty);
        Assert.Null(state.CurrentDestinationConnectionIdSequence);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-19150002")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryAcceptNewConnectionId_WhenZeroLengthModeRejectsFrame_PreservesExistingPeerDestination()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] firstConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] secondConnectionId = [0x30, 0x31, 0x32];

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x01, 0x00, firstConnectionId, CreateStatelessResetToken(0x20)),
            requiresZeroLengthDestinationConnectionId: false,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);

        Assert.False(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x02, 0x00, secondConnectionId, CreateStatelessResetToken(0x40)),
            requiresZeroLengthDestinationConnectionId: true,
            out errorCode,
            out destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Equal(0x01UL, state.CurrentDestinationConnectionIdSequence);
        Assert.True(firstConnectionId.AsSpan().SequenceEqual(state.CurrentDestinationConnectionId.Span));
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

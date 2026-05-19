namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0021")]
public sealed class REQ_QUIC_RFC9000_S19P15_0021
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0021")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryAcceptNewConnectionId_SmallerSubsequentRetirePriorToDoesNotRetireAdditionalConnectionIds()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] initialDestinationConnectionId = [0x01, 0x02, 0x03, 0x04];
        byte[] firstConnectionId = [0x20, 0x21, 0x22];
        byte[] secondConnectionId = [0x40, 0x41, 0x42];
        byte[] thirdConnectionId = [0x60, 0x61, 0x62];

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x02, 0x00, firstConnectionId, QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: initialDestinationConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x04, 0x03, secondConnectionId, QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x50)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: initialDestinationConnectionId,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL, 2UL], retiredSequenceNumbers.OrderBy(sequence => sequence).ToArray());

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x05, 0x01, thirdConnectionId, QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: initialDestinationConnectionId,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);
        Assert.Equal(0x04UL, state.CurrentDestinationConnectionIdSequence);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0220")]
public sealed class REQ_QUIC_RFC9000_0220
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialConnectionIdIsRetiredAsSequenceNumberZero()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionIdStart: 0x10,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 2UL,
            retirePriorTo: 1UL,
            connectionIdStart: 0x20,
            activeConnectionIdLimit: 2UL,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL], retiredSequenceNumbers);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InitialConnectionIdCannotBeReissuedUnderANonZeroSequenceNumber()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] initialDestinationConnectionId = [0x01, 0x02, 0x03];

        Assert.False(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                1UL,
                0UL,
                initialDestinationConnectionId,
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void MaximumLengthInitialConnectionIdIsStillRetiredAsSequenceNumberZero()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] initialDestinationConnectionId = Enumerable
            .Range(0, QuicConnectionIdKey.MaximumLength)
            .Select(value => (byte)(0x80 + value))
            .ToArray();

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                1UL,
                1UL,
                [0x40, 0x41, 0x42],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x40)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL], retiredSequenceNumbers);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0017")]
public sealed class REQ_QUIC_RFC9000_S19P15_0017
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryAcceptNewConnectionId_UsesSequenceNumberToRejectChangedDuplicate()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x02, 0x00, [0x20, 0x21, 0x22], CreateStatelessResetToken(0x30)),
            requiresZeroLengthDestinationConnectionId: false,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);

        Assert.False(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x02, 0x00, [0x24, 0x25, 0x26], CreateStatelessResetToken(0x30)),
            requiresZeroLengthDestinationConnectionId: false,
            out errorCode,
            out destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
        Assert.False(destinationConnectionIdChanged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryHandleApplicationPacketReceived_UsesSequenceNumbersToKeepTheLatestNewConnectionId()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] firstConnectionId = [0x40, 0x41, 0x42];
        byte[] secondConnectionId = [0x50, 0x51, 0x52];
        byte[] statelessResetToken = CreateStatelessResetToken(0x60);

        _ = ProcessNewConnectionIdFrame(runtime, 0x01, 0x00, firstConnectionId, statelessResetToken, observedAtTicks: 8);
        Assert.False(firstConnectionId.AsSpan().SequenceEqual(runtime.CurrentPeerDestinationConnectionId.Span));
        Assert.Null(runtime.TerminalState);

        Assert.True(ProcessNewConnectionIdFrame(runtime, 0x02, 0x01, secondConnectionId, statelessResetToken, observedAtTicks: 9).StateChanged);
        Assert.True(secondConnectionId.AsSpan().SequenceEqual(runtime.CurrentPeerDestinationConnectionId.Span));
        Assert.Null(runtime.TerminalState);

        Assert.True(ProcessNewConnectionIdFrame(runtime, 0x01, 0x00, firstConnectionId, statelessResetToken, observedAtTicks: 10).StateChanged);
        Assert.True(secondConnectionId.AsSpan().SequenceEqual(runtime.CurrentPeerDestinationConnectionId.Span));
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0017")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryAcceptNewConnectionId_OutOfOrderLowerSequenceDoesNotReplaceHigherDestination()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] higherConnectionId = [0x70, 0x71, 0x72];
        byte[] lowerConnectionId = [0x60, 0x61, 0x62];

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x05, 0x00, higherConnectionId, CreateStatelessResetToken(0x80)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: ReadOnlySpan<byte>.Empty,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x03, 0x00, lowerConnectionId, CreateStatelessResetToken(0x90)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: ReadOnlySpan<byte>.Empty,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(0x05UL, state.CurrentDestinationConnectionIdSequence);
        Assert.True(higherConnectionId.AsSpan().SequenceEqual(state.CurrentDestinationConnectionId.Span));
    }

    private static QuicConnectionTransitionResult ProcessNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken,
        long observedAtTicks)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            statelessResetToken));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        byte[] protectedPacket = QuicS17P2P3TestSupport.BuildExpectedOneRttPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            keyPhase: false);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
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

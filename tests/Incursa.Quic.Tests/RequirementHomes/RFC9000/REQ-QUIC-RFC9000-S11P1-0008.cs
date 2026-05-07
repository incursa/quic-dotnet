namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0008">An endpoint MUST NOT discard a packet unless it does not process the frames in the packet or it reverts the effects of any processing.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S11P1-0008")]
public sealed class REQ_QUIC_RFC9000_S11P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRuntimeDoesNotMutateStateWhenATamperedInitialPacketIsDiscarded()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        QuicConnectionPathIdentity path = new("203.0.113.71", RemotePort: 443);

        byte[] protectedInitialPacket = CreateProtectedInitialPacket(initialDestinationConnectionId);
        protectedInitialPacket[^1] ^= 0x80;

        QuicConnectionRuntime runtime = CreateServerRuntime(initialDestinationConnectionId);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                protectedInitialPacket),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.Empty(result.Effects);
        Assert.NotNull(runtime.ActivePath);
        Assert.Equal(path, runtime.ActivePath.Value.Identity);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.False(runtime.TlsState.InitialKeysAvailable);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.Null(runtime.TlsState.HandshakeMessageType);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.Empty(runtime.SendRuntime.SentPackets);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRuntimeDoesNotDiscardValidClientInitialPacketWithPermittedFrames()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        using QuicConnectionRuntime runtime =
            QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(initialDestinationConnectionId);
        QuicConnectionPathIdentity path = new("203.0.113.74", RemotePort: 443);
        QuicConnectionCloseFrame closeFrame = new(QuicTransportErrorCode.NoError, triggeringFrameType: 0x02, []);
        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            initialDestinationConnectionId,
            QuicFrameTestData.BuildConnectionCloseFrame(closeFrame));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                path,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.NoError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ServerRuntimeRevertsPotentialCryptoSideEffectsBeforeDiscardingAnInvalidInitialPacket()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        using QuicConnectionRuntime runtime =
            QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(initialDestinationConnectionId);
        QuicConnectionPathIdentity path = new("203.0.113.75", RemotePort: 443);
        byte[] plaintextPayload =
        [
            .. QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0x60, 0x61, 0x62, 0x63])),
            .. QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0)),
        ];
        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            initialDestinationConnectionId,
            plaintextPayload);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                path,
                protectedPacket),
            nowTicks: 2);

        Assert.True(result.StateChanged || runtime.TerminalState is null);
        if (runtime.TerminalState is { } terminalState)
        {
            Assert.Equal(QuicConnectionCloseOrigin.Local, terminalState.Origin);
            Assert.Equal(QuicTransportErrorCode.ProtocolViolation, terminalState.Close.TransportErrorCode);
        }

        Assert.Equal(0, runtime.TlsState.InitialIngressCryptoBuffer.BufferedBytes);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    private static byte[] CreateProtectedInitialPacket(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: initialDestinationConnectionId,
            sourceConnectionId:
            [
                0x21, 0x22, 0x23, 0x24,
            ],
            token: [],
            packetNumber:
            [
                0x01,
            ],
            plaintextPayload:
            [
                0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22, 0x23,
            ]);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(protection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten));
        Assert.Equal(protectedPacket.Length, bytesWritten);

        return protectedPacket;
    }

    private static QuicConnectionRuntime CreateServerRuntime(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            currentProbeTimeoutMicros: 100,
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        return runtime;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}

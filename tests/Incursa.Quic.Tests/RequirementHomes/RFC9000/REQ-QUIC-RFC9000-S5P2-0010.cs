namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0010")]
public sealed class REQ_QUIC_RFC9000_S5P2_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialPacketOpenSuccessProcessesPermittedPacketContents()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        using QuicConnectionRuntime runtime =
            QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(initialDestinationConnectionId);
        QuicConnectionCloseFrame closeFrame = new(QuicTransportErrorCode.NoError, triggeringFrameType: 0x02, []);
        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            initialDestinationConnectionId,
            QuicFrameTestData.BuildConnectionCloseFrame(closeFrame));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.70", RemotePort: 443),
                protectedPacket),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.NoError, runtime.TerminalState.Value.Close.TransportErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InitialPacketOpenFailureWithAvailableKeysDiscardsPacketContents()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        using QuicConnectionRuntime runtime =
            QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(initialDestinationConnectionId);
        QuicConnectionPathIdentity path = new("203.0.113.70", RemotePort: 443);
        byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
            new QuicCryptoFrame(0, [0x40, 0x41, 0x42, 0x43]));
        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            initialDestinationConnectionId,
            cryptoPayload);
        byte[] tamperedPacket = QuicS5P2PacketAssociationTestSupport.TamperLastByte(protectedPacket);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                tamperedPacket),
            nowTicks: 0);

        Assert.Null(runtime.TerminalState);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(0, runtime.TlsState.InitialIngressCryptoBuffer.BufferedBytes);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void HandshakePacketOpenFailureWithAvailableKeysIsNotDeferred()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        using QuicConnectionRuntime clientRuntime = scenario.ClientRuntime;
        using QuicConnectionRuntime serverRuntime = scenario.ServerRuntime;

        QuicConnectionTransitionResult initialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                scenario.PathIdentity,
                scenario.InitialPacket),
            nowTicks: 10);
        Assert.True(initialResult.StateChanged);
        Assert.True(clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out _));

        byte[] tamperedHandshakePacket =
            QuicS5P2PacketAssociationTestSupport.TamperLastByte(scenario.HandshakePacket);

        QuicConnectionTransitionResult handshakeResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                scenario.PathIdentity,
                tamperedHandshakePacket),
            nowTicks: 11);

        Assert.Null(clientRuntime.TerminalState);
        Assert.False(clientRuntime.TlsState.PeerTransportParametersCommitted);
        Assert.Equal(0, QuicS5P2PacketAssociationTestSupport.GetBufferedEstablishmentHandshakePacketCount(clientRuntime));
        Assert.DoesNotContain(handshakeResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }
}

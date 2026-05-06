namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0012")]
public sealed class REQ_QUIC_RFC9000_S5P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialPacketWithValidPrefixBeforeForbiddenFrameGeneratesProtocolViolation()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        using QuicConnectionRuntime runtime =
            QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(initialDestinationConnectionId);
        byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
            new QuicCryptoFrame(0, [0x50, 0x51, 0x52, 0x53]));
        byte[] resetStreamPayload = QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0));
        byte[] plaintextPayload = [.. cryptoPayload, .. resetStreamPayload];
        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            initialDestinationConnectionId,
            plaintextPayload);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.70", RemotePort: 443),
                protectedPacket),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakePacketWithValidPrefixBeforeForbiddenFrameGeneratesProtocolViolation()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        using QuicConnectionRuntime clientRuntime = scenario.ClientRuntime;
        using QuicConnectionRuntime serverRuntime = scenario.ServerRuntime;

        byte[] prefixThenForbiddenPayload =
        [
            .. QuicFrameTestData.BuildPingFrame(),
            .. QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0)),
        ];
        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedHandshakePacket(
            serverRuntime,
            prefixThenForbiddenPayload);

        QuicConnectionTransitionResult result = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 21,
                scenario.PathIdentity,
                protectedPacket),
            nowTicks: 21);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, serverRuntime.Phase);
        Assert.NotNull(serverRuntime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, serverRuntime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, serverRuntime.TerminalState.Value.Close.TransportErrorCode);
    }
}

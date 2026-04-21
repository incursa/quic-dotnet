namespace Incursa.Quic.Tests;

public sealed class QuicCoalescedPacketRuntimeTests
{
    [Fact]
    public void LeadingServerInitialPacketContainsACryptoFrame()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            scenario.InitialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new(scenario.InitialDestinationConnectionId);
        Assert.True(coordinator.TryOpenInitialPacket(
            scenario.InitialPacket,
            protection,
            requireZeroTokenLength: true,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(payload, out _, out int cryptoBytesConsumed));
        Assert.True(cryptoBytesConsumed > 0);
    }

    [Fact]
    public void LeadingServerInitialPacketInstallsHandshakeOpenMaterial()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.InitialPacket),
            nowTicks: 10);

        string detail = DescribeHandshakeState(scenario.ClientRuntime, result);

        Assert.True(result.StateChanged, detail);
        Assert.True(
            scenario.ClientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out _),
            detail);
        Assert.True(scenario.ClientRuntime.TlsState.HandshakeKeysAvailable, detail);
    }

    [Fact]
    public void LeadingServerInitialPacketDerivesOpenMaterialThatMatchesTheServerHandshakeProtectMaterial()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        _ = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.InitialPacket),
            nowTicks: 10);

        Assert.True(scenario.ClientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial openMaterial));
        Assert.True(scenario.ServerRuntime.TlsState.HandshakeProtectPacketProtectionMaterial.HasValue);
        Assert.True(openMaterial.Matches(scenario.ServerRuntime.TlsState.HandshakeProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    public void TrailingServerHandshakePacketCommitsPeerTransportParametersAfterTheLeadingInitialPacket()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        QuicConnectionTransitionResult initialResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.InitialPacket),
            nowTicks: 10);
        Assert.True(initialResult.StateChanged, DescribeHandshakeState(scenario.ClientRuntime, initialResult));

        QuicConnectionTransitionResult handshakeResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.HandshakePacket),
            nowTicks: 11);

        string detail = DescribeHandshakeState(scenario.ClientRuntime, handshakeResult);

        Assert.True(handshakeResult.StateChanged, detail);
        Assert.True(scenario.ClientRuntime.TlsState.PeerTransportParametersCommitted, detail);
        Assert.NotNull(scenario.ClientRuntime.TlsState.PeerTransportParameters);
    }

    private static string DescribeHandshakeState(QuicConnectionRuntime runtime, QuicConnectionTransitionResult result)
    {
        return string.Join(
            " | ",
            [
                $"stateChanged={result.StateChanged}",
                $"handshakeKeys={runtime.TlsState.HandshakeKeysAvailable}",
                $"handshakeOpenMaterial={runtime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out _)}",
                $"peerTransportParametersCommitted={runtime.TlsState.PeerTransportParametersCommitted}",
                $"terminal={runtime.TlsState.IsTerminal}",
                $"fatalAlert={runtime.TlsState.FatalAlertDescription ?? "<none>"}",
                $"effects={result.Effects.Count()}",
                $"effectTypes={string.Join(",", result.Effects.Select(effect => effect.GetType().Name))}",
                $"diagnostics={string.Join(",", result.Effects.OfType<QuicConnectionEmitDiagnosticEffect>().Select(effect => effect.Diagnostic.Name))}",
            ]);
    }
}

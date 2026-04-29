using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0005">If a key update is not possible or integrity limits are reached, an endpoint MUST send only stateless resets in response to received packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0005")]
public sealed class REQ_QUIC_RFC9001_S6P6_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyAllowsOnlyStatelessResetsAfterConnectionStoppedForAeadLimit()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 16, integrityLimit: 16);

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: true);

        Assert.Equal(QuicAeadLimitAction.SendOnlyStatelessReset, decision.Action);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
        Assert.True(decision.RequiresConnectionStop);
        Assert.True(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeOpenPathDiscardsConnectionWhenIntegrityLimitIsReached()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);

        QuicAeadKeyLifecycle openLifecycle =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReplaceCurrentOneRttOpenKeyLifecycleForTest(runtime);
        Assert.NotNull(openLifecycle);
        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        byte[] paddingPayload = [0x00];

        QuicConnectionTransitionResult result = default;
        for (int packet = 0; packet < QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestIntegrityLimitPackets; packet++)
        {
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                paddingPayload,
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
                keyPhase: false,
                out _,
                out byte[] protectedPacket));

            result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: packet + 1,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: packet + 1);

            if (packet < 127)
            {
                Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
                Assert.Equal(packet + 1d, openLifecycle.OpenedPacketCount);
                Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
            }
        }

        Assert.True(result.StateChanged);
        Assert.Equal(QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestIntegrityLimitPackets, openLifecycle.OpenedPacketCount);
        Assert.True(openLifecycle.HasReachedIntegrityLimit);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeOpenPathDiscardsBeforeUsingExhaustedRetainedOldKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicAeadKeyLifecycle retainedOldOpenLifecycle =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReplaceRetainedOldOneRttOpenKeyLifecycleForTest(runtime);
        Assert.NotNull(retainedOldOpenLifecycle);
        for (int packet = 0; packet < QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestIntegrityLimitPackets; packet++)
        {
            Assert.True(retainedOldOpenLifecycle.TryUseForOpening());
        }

        Assert.True(retainedOldOpenLifecycle.HasReachedIntegrityLimit);

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            [0x00],
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value,
            keyPhase: false,
            out _,
            out byte[] protectedPacket));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 129,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: 129);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestIntegrityLimitPackets, retainedOldOpenLifecycle.OpenedPacketCount);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointPreservesStatelessResetOnlyEmissionAfterAeadLimitDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC0);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 6605UL, token));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());

        Assert.True(endpoint.TryApplyEffect(handle, discard));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagram(
            handle,
            6605UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.True(emission.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(pathIdentity, emission.PathIdentity);
        Assert.Equal(99, emission.Datagram.Length);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(emission.Datagram.Span));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotFabricateStatelessResetOnlyEmissionAfterAeadLimitDiscardWithoutToken()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());

        Assert.True(endpoint.TryApplyEffect(handle, discard));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagram(
            handle,
            6605UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointAutomaticallyCreatesStatelessResetForRetainedRouteAfterAeadLimitDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x05, 0xA0, 0x01];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC1);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: 6605UL));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 6605UL, token));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());

        Assert.True(endpoint.TryApplyEffect(handle, discard));

        byte[] triggeringPacket = CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 72);
        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.True(emission.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(pathIdentity, emission.PathIdentity);
        Assert.Equal(triggeringPacket.Length - 1, emission.Datagram.Length);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointAutomaticallyCreatesStatelessResetForRetainedLongHeaderRouteAfterAeadLimitDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x05, 0xB0, 0x01];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC5);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: 7605UL));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 7605UL, token));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());

        Assert.True(endpoint.TryApplyEffect(handle, discard));

        byte[] triggeringPacket = CreateRetainedRouteLongHeaderDatagram(routeConnectionId);
        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.True(emission.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(pathIdentity, emission.PathIdentity);
        Assert.Equal(triggeringPacket.Length - 1, emission.Datagram.Length);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task EndpointHostSendsStatelessResetForRetainedRouteAfterAeadLimitDiscard()
    {
        using Socket serverSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        serverSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        IPEndPoint serverEndPoint = (IPEndPoint)serverSocket.LocalEndPoint!;
        IPEndPoint clientEndPoint = (IPEndPoint)clientSocket.LocalEndPoint!;
        serverSocket.Connect(clientEndPoint);
        clientSocket.Connect(serverEndPoint);

        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
        byte[] routeConnectionId = [0x66, 0x05, 0xA0, 0x02];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC2);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: 6605UL));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 6605UL, token));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());
        Assert.True(endpoint.TryApplyEffect(handle, discard));

        await using QuicConnectionEndpointHost host = new(endpoint, serverSocket, pathIdentity);
        _ = host.RunAsync();

        byte[] triggeringPacket = CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 80);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token);

        Assert.Equal(triggeringPacket.Length - 1, bytesReceived);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(response.AsSpan(0, bytesReceived)));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(response.AsSpan(0, bytesReceived), token);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task EndpointHostSendsStatelessResetForRetainedLongHeaderRouteAfterAeadLimitDiscard()
    {
        using Socket serverSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        serverSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        IPEndPoint serverEndPoint = (IPEndPoint)serverSocket.LocalEndPoint!;
        IPEndPoint clientEndPoint = (IPEndPoint)clientSocket.LocalEndPoint!;
        serverSocket.Connect(clientEndPoint);
        clientSocket.Connect(serverEndPoint);

        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
        byte[] routeConnectionId = [0x66, 0x05, 0xB0, 0x02];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC6);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: 6605UL));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 6605UL, token));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());
        Assert.True(endpoint.TryApplyEffect(handle, discard));

        await using QuicConnectionEndpointHost host = new(endpoint, serverSocket, pathIdentity);
        _ = host.RunAsync();

        byte[] triggeringPacket = CreateRetainedRouteLongHeaderDatagram(routeConnectionId);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token);

        Assert.Equal(triggeringPacket.Length - 1, bytesReceived);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(response.AsSpan(0, bytesReceived)));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(response.AsSpan(0, bytesReceived), token);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ListenerHostSendsStatelessResetForRetainedRouteAfterAeadLimitDiscard()
    {
        await using QuicListenerHost listenerHost = new(
            new IPEndPoint(IPAddress.Loopback, 0),
            [new SslApplicationProtocol("h3")],
            static (_, _, _) => throw new InvalidOperationException("No connection acceptance is expected for retained-route reset response."),
            listenBacklog: 1);
        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        Socket listenerSocket = GetPrivateField<Socket>(listenerHost, "socket");
        QuicConnectionRuntimeEndpoint endpoint = GetPrivateField<QuicConnectionRuntimeEndpoint>(listenerHost, "endpoint");
        IPEndPoint serverEndPoint = (IPEndPoint)listenerSocket.LocalEndPoint!;
        clientSocket.Connect(serverEndPoint);
        IPEndPoint clientEndPoint = (IPEndPoint)clientSocket.LocalEndPoint!;

        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
        byte[] routeConnectionId = [0x66, 0x05, 0xA0, 0x04];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC4);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: 6605UL));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 6605UL, token));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());
        Assert.True(endpoint.TryApplyEffect(handle, discard));

        _ = listenerHost.RunAsync();

        byte[] triggeringPacket = CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 88);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token);

        Assert.Equal(triggeringPacket.Length - 1, bytesReceived);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(response.AsSpan(0, bytesReceived)));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(response.AsSpan(0, bytesReceived), token);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ListenerHostSendsStatelessResetForRetainedLongHeaderRouteAfterAeadLimitDiscard()
    {
        await using QuicListenerHost listenerHost = new(
            new IPEndPoint(IPAddress.Loopback, 0),
            [new SslApplicationProtocol("h3")],
            static (_, _, _) => throw new InvalidOperationException("No connection acceptance is expected for retained-route reset response."),
            listenBacklog: 1);
        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        Socket listenerSocket = GetPrivateField<Socket>(listenerHost, "socket");
        QuicConnectionRuntimeEndpoint endpoint = GetPrivateField<QuicConnectionRuntimeEndpoint>(listenerHost, "endpoint");
        IPEndPoint serverEndPoint = (IPEndPoint)listenerSocket.LocalEndPoint!;
        clientSocket.Connect(serverEndPoint);
        IPEndPoint clientEndPoint = (IPEndPoint)clientSocket.LocalEndPoint!;

        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
        byte[] routeConnectionId = [0x66, 0x05, 0xB0, 0x03];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC7);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: 6605UL));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 6605UL, token));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());
        Assert.True(endpoint.TryApplyEffect(handle, discard));

        _ = listenerHost.RunAsync();

        byte[] triggeringPacket = CreateRetainedRouteLongHeaderDatagram(routeConnectionId);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token);

        Assert.Equal(triggeringPacket.Length - 1, bytesReceived);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(response.AsSpan(0, bytesReceived)));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(response.AsSpan(0, bytesReceived), token);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotAutomaticallyResetUnlinkedRoutesAfterAeadLimitDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x05, 0xA0, 0x03];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC3);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 6605UL, token));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());

        Assert.True(endpoint.TryApplyEffect(handle, discard));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 72),
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyAllowsOnlyStatelessResetsAfterIntegrityLimitIsReached()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 16, integrityLimit: 1);

        Assert.True(keyLifecycle.TryUseForOpening());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: false);

        Assert.Equal(QuicAeadLimitAction.SendOnlyStatelessReset, decision.Action);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
        Assert.True(decision.RequiresConnectionStop);
        Assert.True(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AeadLimitPolicyKeepsOrdinaryResponsesBeforeAeadStop()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 4, integrityLimit: 4);

        Assert.True(keyLifecycle.TryUseForOpening());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: false);

        Assert.Equal(QuicAeadLimitAction.Continue, decision.Action);
        Assert.Null(decision.TransportErrorCode);
        Assert.False(decision.RequiresConnectionStop);
        Assert.False(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzStatelessResetOnlyPolicy_RandomizedIntegrityLimitsChooseStatelessResetOnly()
    {
        Random random = new(unchecked((int)0x9001_6605));

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int integrityLimit = random.Next(1, 24);
            QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 128, integrityLimit);

            for (int packet = 0; packet < integrityLimit; packet++)
            {
                Assert.True(keyLifecycle.TryUseForOpening());
            }

            QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
                keyLifecycle,
                connectionStoppedForAeadLimit: false);

            Assert.Equal(QuicAeadLimitAction.SendOnlyStatelessReset, decision.Action);
            Assert.True(decision.AllowsOnlyStatelessReset);
            Assert.Equal((double)integrityLimit, keyLifecycle.OpenedPacketCount);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzEndpointStatelessResetOnlyEmissionAfterAeadLimitDiscard_RespectsLoopAndRateGates()
    {
        Random random = new(unchecked((int)0x9001_6655));

        for (int iteration = 0; iteration < 24; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0xD0 + iteration));
            bool hasLoopPreventionState = random.Next(0, 2) == 0;
            int triggeringPacketLength = QuicStatelessReset.MinimumDatagramLength + random.Next(0, 32);

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
            Assert.True(endpoint.TryRegisterStatelessResetToken(handle, (ulong)(7000 + iteration), token));
            Assert.True(endpoint.TryApplyEffect(
                handle,
                new QuicConnectionDiscardConnectionStateEffect(CreateAeadLimitTerminalState(iteration))));

            QuicConnectionStatelessResetEmissionResult first = endpoint.TryCreateStatelessResetDatagram(
                handle,
                (ulong)(7000 + iteration),
                triggeringPacketLength,
                hasLoopPreventionState);

            if (triggeringPacketLength == QuicStatelessReset.MinimumDatagramLength && !hasLoopPreventionState)
            {
                Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.LoopOrAmplificationPrevented, first.Disposition);
                Assert.False(first.Emitted);
                continue;
            }

            Assert.True(first.Emitted);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, first.Disposition);
            Assert.Equal(pathIdentity, first.PathIdentity);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(first.Datagram.Span, token);

            QuicConnectionStatelessResetEmissionResult second = endpoint.TryCreateStatelessResetDatagram(
                handle,
                (ulong)(7000 + iteration),
                triggeringPacketLength,
                hasLoopPreventionState);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.RateLimited, second.Disposition);
            Assert.False(second.Emitted);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzEndpointRetainedRouteStatelessResetResponse_RequiresLinkedTokenPathAndRateBudget()
    {
        Random random = new(unchecked((int)0x9001_6656));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            byte[] routeConnectionId =
            [
                0x66,
                0x05,
                unchecked((byte)iteration),
                unchecked((byte)random.Next(1, 255)),
            ];
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0xE0 + iteration));
            ulong resetConnectionId = (ulong)(7600 + iteration);
            bool linkRouteToToken = random.Next(0, 2) == 0;
            bool useSameRemotePath = random.Next(0, 2) == 0;
            QuicConnectionPathIdentity retainedPath = new(
                "203.0.113.66",
                "198.51.100.66",
                6605,
                4433);
            QuicConnectionPathIdentity triggerPath = useSameRemotePath
                ? retainedPath
                : retainedPath with { RemotePort = 6606 };

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(linkRouteToToken
                ? endpoint.TryRegisterConnectionId(handle, routeConnectionId, resetConnectionId)
                : endpoint.TryRegisterConnectionId(handle, routeConnectionId));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, retainedPath));
            Assert.True(endpoint.TryRegisterStatelessResetToken(handle, resetConnectionId, token));
            Assert.True(endpoint.TryApplyEffect(
                handle,
                new QuicConnectionDiscardConnectionStateEffect(CreateAeadLimitTerminalState(iteration))));

            byte[] triggeringPacket = random.Next(0, 2) == 0
                ? CreateRetainedRouteShortHeaderDatagram(
                    routeConnectionId,
                    triggeringPacketLength: QuicStatelessReset.MinimumDatagramLength + 8 + random.Next(0, 16))
                : CreateRetainedRouteLongHeaderDatagram(routeConnectionId);
            QuicConnectionStatelessResetEmissionResult first = endpoint.TryCreateStatelessResetDatagramForPacket(
                triggeringPacket,
                triggerPath,
                hasLoopPreventionState: true);

            if (!linkRouteToToken || !useSameRemotePath)
            {
                Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, first.Disposition);
                Assert.False(first.Emitted);
                continue;
            }

            Assert.True(first.Emitted);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, first.Disposition);
            Assert.Equal(triggerPath, first.PathIdentity);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(first.Datagram.Span, token);

            QuicConnectionStatelessResetEmissionResult second = endpoint.TryCreateStatelessResetDatagramForPacket(
                triggeringPacket,
                triggerPath,
                hasLoopPreventionState: true);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.RateLimited, second.Disposition);
            Assert.False(second.Emitted);
        }
    }

    private static QuicAeadKeyLifecycle CreateActiveLifecycle(int confidentialityLimit, int integrityLimit)
    {
        QuicAeadKeyLifecycle keyLifecycle = new(new QuicAeadUsageLimits(confidentialityLimit, integrityLimit));
        Assert.True(keyLifecycle.TryActivate());
        return keyLifecycle;
    }

    private static QuicConnectionTransitionResult ExhaustCurrentOpenIntegrityLimit(QuicConnectionRuntime runtime)
    {
        QuicAeadKeyLifecycle openLifecycle =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReplaceCurrentOneRttOpenKeyLifecycleForTest(runtime);
        Assert.NotNull(openLifecycle);
        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        byte[] paddingPayload = [0x00];
        QuicConnectionTransitionResult result = default;

        for (int packet = 0; packet < QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestIntegrityLimitPackets; packet++)
        {
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                paddingPayload,
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
                keyPhase: false,
                out _,
                out byte[] protectedPacket));

            result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: packet + 1,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: packet + 1);
        }

        Assert.Equal(QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestIntegrityLimitPackets, openLifecycle.OpenedPacketCount);
        Assert.True(openLifecycle.HasReachedIntegrityLimit);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, runtime.TerminalState?.Close.TransportErrorCode);
        return result;
    }

    private static byte[] CreateRetainedRouteShortHeaderDatagram(
        ReadOnlySpan<byte> routeConnectionId,
        int triggeringPacketLength)
    {
        Assert.True(triggeringPacketLength > 1 + routeConnectionId.Length);

        byte[] remainder = new byte[triggeringPacketLength - 1];
        routeConnectionId.CopyTo(remainder);
        for (int offset = routeConnectionId.Length; offset < remainder.Length; offset++)
        {
            remainder[offset] = unchecked((byte)(0xA0 + offset));
        }

        return QuicHeaderTestData.BuildShortHeader(0x00, remainder);
    }

    private static byte[] CreateRetainedRouteLongHeaderDatagram(ReadOnlySpan<byte> routeConnectionId)
    {
        return QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: routeConnectionId.ToArray(),
            sourceConnectionId: [0x51, 0x52],
            protectedPayload: [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5]);
    }

    private static T GetPrivateField<T>(object target, string fieldName)
    {
        FieldInfo? field = target.GetType().GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        return Assert.IsType<T>(field.GetValue(target));
    }

    private static QuicConnectionTerminalState CreateAeadLimitTerminalState(int enteredAtTicks)
    {
        return new QuicConnectionTerminalState(
            QuicConnectionPhase.Discarded,
            QuicConnectionCloseOrigin.Local,
            new QuicConnectionCloseMetadata(
                QuicTransportErrorCode.AeadLimitReached,
                ApplicationErrorCode: null,
                TriggeringFrameType: null,
                ReasonPhrase: "The connection reached the AEAD limit."),
            enteredAtTicks);
    }
}

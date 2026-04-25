using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0006">After AEAD-limit terminal discard, an endpoint MUST emit a stateless reset for a later received packet only when the packet resolves to a retained route linked to a remembered stateless-reset token for the same remote address and port, and the loop-prevention and emission-rate gates permit the response; otherwise it MUST suppress the response.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0006")]
public sealed class REQ_QUIC_RFC9001_S6P6_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointAutomaticallyCreatesStatelessResetForRetainedRouteAfterAeadLimitDiscardWhenRemotePortMatches()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x06, 0xA0, 0x01];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xD1);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId, 6606UL, token, enteredAtTicks: 1);

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
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotCreateStatelessResetForRetainedRouteAfterAeadLimitDiscardWhenRemotePortDiffers()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        QuicConnectionPathIdentity triggerPath = pathIdentity with { RemotePort = pathIdentity.RemotePort + 1 };
        byte[] routeConnectionId = [0x66, 0x06, 0xA0, 0x02];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xD2);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId, 6606UL, token, enteredAtTicks: 2);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 72),
            triggerPath,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotCreateStatelessResetForRetainedRouteAfterAeadLimitDiscardWithoutLoopPreventionState()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x06, 0xA0, 0x03];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xD3);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId, 6606UL, token, enteredAtTicks: 3);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: QuicStatelessReset.MinimumDatagramLength),
            pathIdentity,
            hasLoopPreventionState: false);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.LoopOrAmplificationPrevented, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotCreateStatelessResetForRetainedRouteAfterAeadLimitDiscardWhenRemoteAddressDiffers()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        QuicConnectionPathIdentity triggerPath = pathIdentity with { RemoteAddress = "203.0.113.67" };
        byte[] routeConnectionId = [0x66, 0x06, 0xA0, 0x04];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xD4);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId, 6606UL, token, enteredAtTicks: 4);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 72),
            triggerPath,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzEndpointRetainedRouteStatelessResetResponse_RequiresPortMatchLoopBudgetAndRateBudget()
    {
        Random random = new(unchecked((int)0x9001_6606));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
            QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity retainedPath = new(
                "203.0.113.66",
                "198.51.100.66",
                6605,
                4433);
            bool useSameRemotePort = random.Next(0, 2) == 0;
            bool hasLoopPreventionState = random.Next(0, 2) == 0;
            int triggeringPacketLength = random.Next(0, 2) == 0
                ? QuicStatelessReset.MinimumDatagramLength
                : QuicStatelessReset.MinimumDatagramLength + random.Next(1, 24);
            QuicConnectionPathIdentity triggerPath = useSameRemotePort
                ? retainedPath
                : retainedPath with { RemotePort = retainedPath.RemotePort + 1 };
            byte[] routeConnectionId = [0x66, 0x06, unchecked((byte)iteration), unchecked((byte)random.Next(1, 255))];
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0xE0 + iteration));
            ulong resetConnectionId = (ulong)(7606 + iteration);

            ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, retainedPath, routeConnectionId, resetConnectionId, token, enteredAtTicks: iteration + 1);

            QuicConnectionStatelessResetEmissionResult first = endpoint.TryCreateStatelessResetDatagramForPacket(
                CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength),
                triggerPath,
                hasLoopPreventionState);

            if (!useSameRemotePort)
            {
                Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, first.Disposition);
                Assert.False(first.Emitted);
                continue;
            }

            if (triggeringPacketLength == QuicStatelessReset.MinimumDatagramLength && !hasLoopPreventionState)
            {
                Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.LoopOrAmplificationPrevented, first.Disposition);
                Assert.False(first.Emitted);
                continue;
            }

            Assert.True(first.Emitted);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, first.Disposition);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(first.Datagram.Span, token);

            QuicConnectionStatelessResetEmissionResult second = endpoint.TryCreateStatelessResetDatagramForPacket(
                CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength),
                triggerPath,
                hasLoopPreventionState);

            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.RateLimited, second.Disposition);
            Assert.False(second.Emitted);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task EndpointHostDoesNotSendStatelessResetForRetainedRouteAfterAeadLimitDiscardWhenRemotePortDiffers()
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
        QuicConnectionPathIdentity retainedPath = new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
        QuicConnectionPathIdentity mismatchedPath = retainedPath with
        {
            RemotePort = retainedPath.RemotePort == ushort.MaxValue ? retainedPath.RemotePort - 1 : retainedPath.RemotePort + 1,
        };
        byte[] routeConnectionId = [0x66, 0x06, 0xA0, 0x05];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xD4);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, mismatchedPath, routeConnectionId, 6606UL, token, enteredAtTicks: 5);

        await using QuicConnectionEndpointHost host = new(endpoint, serverSocket, retainedPath);
        _ = host.RunAsync();

        byte[] triggeringPacket = CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 80);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromMilliseconds(750));
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            retainedPath,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task EndpointHostDoesNotSendStatelessResetForRetainedRouteAfterAeadLimitDiscardWhenRemoteAddressDiffers()
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
        QuicConnectionPathIdentity retainedPath = new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
        QuicConnectionPathIdentity mismatchedPath = retainedPath with
        {
            RemoteAddress = "203.0.113.67",
        };
        byte[] routeConnectionId = [0x66, 0x06, 0xA0, 0x07];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xD6);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, mismatchedPath, routeConnectionId, 6606UL, token, enteredAtTicks: 7);

        await using QuicConnectionEndpointHost host = new(endpoint, serverSocket, retainedPath);
        _ = host.RunAsync();

        byte[] triggeringPacket = CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 88);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromMilliseconds(750));
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            retainedPath,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ListenerHostDoesNotSendStatelessResetForRetainedRouteAfterAeadLimitDiscardWhenRemotePortDiffers()
    {
        await using QuicListenerHost listenerHost = new(
            new IPEndPoint(IPAddress.Loopback, 0),
            [new SslApplicationProtocol("h3")],
            static (_, _, _) => throw new InvalidOperationException("No connection acceptance is expected for retained-route reset suppression."),
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
        QuicConnectionPathIdentity retainedPath = new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
        QuicConnectionPathIdentity mismatchedPath = retainedPath with
        {
            RemotePort = retainedPath.RemotePort == ushort.MaxValue ? retainedPath.RemotePort - 1 : retainedPath.RemotePort + 1,
        };
        byte[] routeConnectionId = [0x66, 0x06, 0xA0, 0x06];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xD5);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, mismatchedPath, routeConnectionId, 6606UL, token, enteredAtTicks: 6);

        _ = listenerHost.RunAsync();

        byte[] triggeringPacket = CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 84);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromMilliseconds(750));
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            retainedPath,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ListenerHostDoesNotSendStatelessResetForRetainedRouteAfterAeadLimitDiscardWhenRemoteAddressDiffers()
    {
        await using QuicListenerHost listenerHost = new(
            new IPEndPoint(IPAddress.Loopback, 0),
            [new SslApplicationProtocol("h3")],
            static (_, _, _) => throw new InvalidOperationException("No connection acceptance is expected for retained-route reset suppression."),
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
        QuicConnectionPathIdentity retainedPath = new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
        QuicConnectionPathIdentity mismatchedPath = retainedPath with
        {
            RemoteAddress = "203.0.113.67",
        };
        byte[] routeConnectionId = [0x66, 0x06, 0xA0, 0x08];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xD7);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, mismatchedPath, routeConnectionId, 6606UL, token, enteredAtTicks: 8);

        _ = listenerHost.RunAsync();

        byte[] triggeringPacket = CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 92);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromMilliseconds(750));
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            retainedPath,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
    }

    private static void ConfigureDiscardedRetainedRouteEndpoint(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionRuntime runtime,
        QuicConnectionHandle handle,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> routeConnectionId,
        ulong resetConnectionId,
        ReadOnlySpan<byte> token,
        int enteredAtTicks)
    {
        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: resetConnectionId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, resetConnectionId, token));
        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionDiscardConnectionStateEffect(CreateAeadLimitTerminalState(enteredAtTicks))));
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

    private static T GetPrivateField<T>(object target, string fieldName)
    {
        FieldInfo? field = target.GetType().GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        return Assert.IsType<T>(field!.GetValue(target));
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

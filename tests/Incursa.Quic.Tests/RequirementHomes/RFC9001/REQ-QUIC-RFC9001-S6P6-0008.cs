using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0008">After AEAD-limit terminal discard, when a later retained-route trigger has Stateless Reset shape and its trailing token matches the retained token for the same remote address and port, the endpoint MUST suppress stateless-reset response emission rather than emitting another stateless reset.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0008")]
public sealed class REQ_QUIC_RFC9001_S6P6_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointSuppressesRetainedRouteResponseWhenTriggerCarriesTheRetainedToken()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x08, 0xA0, 0x01];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x81);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId, 6608UL, token, enteredAtTicks: 1);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            CreateRetainedRouteKnownResetDatagram(routeConnectionId, triggeringPacketLength: 80, token),
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.StatelessResetLoopSuppressed, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.Equal(pathIdentity, emission.PathIdentity);
        Assert.True(emission.Datagram.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointStillEmitsRetainedRouteResponseWhenTriggerCarriesADifferentToken()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x08, 0xA0, 0x02];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x82);
        byte[] differentToken = QuicStatelessResetRequirementTestData.CreateToken(0x83);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId, 6608UL, token, enteredAtTicks: 2);

        byte[] triggeringPacket = CreateRetainedRouteKnownResetDatagram(routeConnectionId, triggeringPacketLength: 80, differentToken);
        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.True(emission.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(triggeringPacket.Length - 1, emission.Datagram.Length);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotTreatNonResetShapedRetainedRoutePacketsAsKnownResets()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x08, 0xA0, 0x03];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x84);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId, 6608UL, token, enteredAtTicks: 3);

        byte[] triggeringPacket = CreateRetainedRouteLongHeaderDatagram(routeConnectionId, token);
        Assert.False(QuicStatelessReset.IsPotentialStatelessReset(triggeringPacket));
        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.True(emission.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(triggeringPacket.Length - 1, emission.Datagram.Length);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task EndpointHostDoesNotSendAResetInResponseToAKnownResetTrigger()
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
        byte[] routeConnectionId = [0x66, 0x08, 0xA0, 0x04];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x85);

        ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId, 6608UL, token, enteredAtTicks: 4);

        await using QuicConnectionEndpointHost host = new(endpoint, serverSocket, pathIdentity);
        _ = host.RunAsync();

        byte[] triggeringPacket = CreateRetainedRouteKnownResetDatagram(routeConnectionId, triggeringPacketLength: 80, token);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromMilliseconds(750));
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.StatelessResetLoopSuppressed, emission.Disposition);
        Assert.False(emission.Emitted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzEndpointRetainedRouteKnownResetSuppression_RequiresMatchingTokenRouteAndRemoteEndpoint()
    {
        Random random = new(unchecked((int)0x9001_6608));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
            QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity retainedPath = new(
                "203.0.113.68",
                "198.51.100.68",
                6608,
                4433);
            bool useSameRemoteAddress = random.Next(0, 2) == 0;
            bool useSameRemotePort = random.Next(0, 2) == 0;
            bool useMatchingToken = random.Next(0, 2) == 0;
            QuicConnectionPathIdentity triggerPath = retainedPath;
            if (!useSameRemoteAddress)
            {
                triggerPath = triggerPath with { RemoteAddress = $"203.0.113.{180 + iteration}" };
            }

            if (!useSameRemotePort)
            {
                triggerPath = triggerPath with { RemotePort = retainedPath.RemotePort + 1 };
            }

            byte[] routeConnectionId = [0x66, 0x08, unchecked((byte)iteration), unchecked((byte)random.Next(1, 255))];
            byte[] retainedToken = QuicStatelessResetRequirementTestData.CreateToken((byte)(0x90 + iteration));
            byte[] triggerToken = useMatchingToken
                ? retainedToken
                : QuicStatelessResetRequirementTestData.CreateToken((byte)(0x40 + iteration));
            ulong resetConnectionId = (ulong)(7608 + iteration);

            ConfigureDiscardedRetainedRouteEndpoint(endpoint, runtime, handle, retainedPath, routeConnectionId, resetConnectionId, retainedToken, enteredAtTicks: iteration + 1);

            byte[] triggeringPacket = CreateRetainedRouteKnownResetDatagram(
                routeConnectionId,
                triggeringPacketLength: QuicStatelessReset.MinimumDatagramLength + 16 + random.Next(0, 16),
                triggerToken);
            QuicConnectionStatelessResetEmissionResult first = endpoint.TryCreateStatelessResetDatagramForPacket(
                triggeringPacket,
                triggerPath,
                hasLoopPreventionState: true);

            if (!useSameRemoteAddress || !useSameRemotePort)
            {
                Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, first.Disposition);
                Assert.False(first.Emitted);
                continue;
            }

            if (useMatchingToken)
            {
                Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.StatelessResetLoopSuppressed, first.Disposition);
                Assert.False(first.Emitted);
                continue;
            }

            Assert.True(first.Emitted);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, first.Disposition);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(first.Datagram.Span, retainedToken);

            QuicConnectionStatelessResetEmissionResult second = endpoint.TryCreateStatelessResetDatagramForPacket(
                triggeringPacket,
                triggerPath,
                hasLoopPreventionState: true);

            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.RateLimited, second.Disposition);
            Assert.False(second.Emitted);
        }
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

    private static byte[] CreateRetainedRouteKnownResetDatagram(
        ReadOnlySpan<byte> routeConnectionId,
        int triggeringPacketLength,
        ReadOnlySpan<byte> token)
    {
        Assert.True(token.Length == QuicStatelessReset.StatelessResetTokenLength);
        Assert.True(triggeringPacketLength > 1 + routeConnectionId.Length + token.Length);

        byte[] datagram = CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength);
        token.CopyTo(datagram.AsSpan(datagram.Length - QuicStatelessReset.StatelessResetTokenLength));
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(datagram));
        return datagram;
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

    private static byte[] CreateRetainedRouteLongHeaderDatagram(
        ReadOnlySpan<byte> routeConnectionId,
        ReadOnlySpan<byte> token)
    {
        byte[] protectedPayload = new byte[24];
        for (int offset = 0; offset < protectedPayload.Length; offset++)
        {
            protectedPayload[offset] = unchecked((byte)(0x90 + offset));
        }

        token.CopyTo(protectedPayload.AsSpan(protectedPayload.Length - QuicStatelessReset.StatelessResetTokenLength));
        return QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: routeConnectionId.ToArray(),
            sourceConnectionId: [0x61, 0x62],
            protectedPayload: protectedPayload);
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

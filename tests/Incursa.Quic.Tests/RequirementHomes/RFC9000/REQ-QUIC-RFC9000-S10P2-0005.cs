using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2-0005">The endpoint MAY send a Stateless Reset in response to any further incoming packets belonging to this connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2-0005")]
public sealed class REQ_QUIC_RFC9000_S10P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S10P2-0005")]
    public async Task EndpointHostSendsStatelessResetForRetainedRoutePacketsAfterDiscard()
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
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
        byte[] routeConnectionId = [0x66, 0x02, 0xA0, 0x05];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x95);

        QuicStatelessResetEndpointHostTestSupport.ConfigureDiscardedRetainedRouteEndpoint(
            endpoint,
            runtime,
            handle,
            pathIdentity,
            routeConnectionId,
            resetConnectionId: 105UL,
            token,
            enteredAtTicks: 1);

        await using QuicConnectionEndpointHost host = new(endpoint, serverSocket, pathIdentity);
        _ = host.RunAsync();

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            routeConnectionId,
            triggeringPacketLength: 80);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token);

        Assert.Equal(triggeringPacket.Length - 1, bytesReceived);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(response.AsSpan(0, bytesReceived)));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(response.AsSpan(0, bytesReceived), token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S10P2-0005")]
    public void TryCreateStatelessResetDatagramForPacket_DoesNotEmitBeforeDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.105", RemotePort: 443);
        byte[] routeConnectionId = [0x66, 0x02, 0xA0, 0x06];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x96);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: 106UL));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 106UL, token));

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            routeConnectionId,
            triggeringPacketLength: 80);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
    }
}

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0015">An endpoint MAY send a Stateless Reset in response to a packet with a long header.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0015")]
public sealed class REQ_QUIC_RFC9000_S10P3_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task EndpointHostSendsStatelessResetForALongHeaderPacket()
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
        byte[] routeConnectionId = [0x66, 0x01, 0xA0, 0x02];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x92);

        QuicStatelessResetEndpointHostTestSupport.ConfigureDiscardedRetainedRouteEndpoint(
            endpoint,
            runtime,
            handle,
            pathIdentity,
            routeConnectionId,
            resetConnectionId: 115UL,
            token,
            enteredAtTicks: 1);

        await using QuicConnectionEndpointHost host = new(endpoint, serverSocket, pathIdentity);
        _ = host.RunAsync();

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteLongHeaderDatagram(routeConnectionId);
        Assert.Equal(triggeringPacket.Length, clientSocket.Send(triggeringPacket));

        byte[] response = new byte[triggeringPacket.Length];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token);

        Assert.Equal(triggeringPacket.Length - 1, bytesReceived);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(response.AsSpan(0, bytesReceived)));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(response.AsSpan(0, bytesReceived), token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreateStatelessResetDatagram_AllowsLongHeaderSizedTriggers()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.92");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x92);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 115UL, token));

        byte[] longHeaderPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x52,
            version: 0x01020304,
            destinationConnectionId: [0x11, 0x12, 0x13, 0x14],
            sourceConnectionId: [0x21, 0x22, 0x23, 0x24],
            versionSpecificData: [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B]);

        QuicConnectionStatelessResetEmissionResult result = endpoint.TryCreateStatelessResetDatagram(
            handle,
            115UL,
            triggeringPacketLength: longHeaderPacket.Length,
            hasLoopPreventionState: false);

        Assert.True(result.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, result.Disposition);
        Assert.Equal(pathIdentity, result.PathIdentity);
        Assert.Equal(longHeaderPacket.Length - 1, result.Datagram.Length);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(result.Datagram.Span));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(result.Datagram.Span, token);
    }
}

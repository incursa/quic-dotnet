using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0007">A server MAY also immediately close the connection by sending a CONNECTION_CLOSE frame with an error code of PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P1-0007")]
public sealed class REQ_QUIC_RFC9000_S14P1_0007
{
    private const int InitialRouteDatagramOverhead = 20;

    private static readonly byte[] DestinationConnectionId = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    private static readonly byte[] SourceConnectionId = [0x20];

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task ListenerHostClosesUndersizedInitialDatagramsWithProtocolViolation()
    {
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        await using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            (_, _, _) =>
            {
                callbackEntered.TrySetResult(true);
                return ValueTask.FromResult(new QuicServerConnectionOptions());
            },
            listenBacklog: 1);

        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        clientSocket.Connect(listenEndPoint);

        _ = listenerHost.RunAsync();
        await Task.Yield();

        byte[] datagram = BuildInitialDatagram(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1);
        int bytesSent = clientSocket.Send(datagram);
        Assert.Equal(datagram.Length, bytesSent);

        byte[] responseBuffer = new byte[64];
        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(responseBuffer.AsMemory(), SocketFlags.None, receiveTimeout.Token);

        byte[] expectedClose = QuicFrameTestData.BuildConnectionCloseFrame(
            new QuicConnectionCloseFrame(
                QuicTransportErrorCode.ProtocolViolation,
                triggeringFrameType: 0,
                []));

        Assert.Equal(expectedClose.Length, bytesReceived);
        Assert.True(expectedClose.AsSpan().SequenceEqual(responseBuffer.AsSpan(0, bytesReceived)));
        Assert.False(callbackEntered.Task.IsCompleted);
    }

    private static byte[] BuildInitialDatagram(int datagramPayloadLength)
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: QuicVersionNegotiation.Version1,
            destinationConnectionId: DestinationConnectionId,
            sourceConnectionId: SourceConnectionId,
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: new byte[datagramPayloadLength - InitialRouteDatagramOverhead]));
    }
}

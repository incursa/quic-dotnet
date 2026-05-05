using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

internal static class QuicS5P2P2ServerPreAcceptanceTestSupport
{
    internal const uint UnsupportedVersion = 0x11223344;

    internal static readonly uint[] SupportedVersions = [QuicVersionNegotiation.Version1];

    internal static byte[] BuildUnsupportedVersionDatagram(int length)
    {
        return BuildLongHeaderDatagram(
            length,
            UnsupportedVersion,
            QuicLongPacketTypeBits.Initial,
            [0x10, 0x11],
            [0x20, 0x21]);
    }

    internal static byte[] BuildVersion1InitialDatagram(int length)
    {
        byte[] datagram = QuicHeaderTestData.BuildLongHeader(
            0x40,
            QuicVersionNegotiation.Version1,
            [0x10, 0x11],
            [0x20, 0x21],
            QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], [0xAA]));

        Assert.True(datagram.Length <= length);
        Array.Resize(ref datagram, length);
        return datagram;
    }

    internal static byte[] BuildVersion1HandshakeDatagram(ReadOnlySpan<byte> destinationConnectionId = default)
    {
        byte[] routeId = destinationConnectionId.IsEmpty ? [0x30, 0x31] : destinationConnectionId.ToArray();
        return QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: routeId,
            sourceConnectionId: [0x40, 0x41]);
    }

    internal static byte[] BuildShortHeaderDatagram(ReadOnlySpan<byte> destinationConnectionId = default)
    {
        return destinationConnectionId.IsEmpty
            ? QuicHeaderTestData.BuildShortHeader(0x00, [0xA0])
            : QuicHeaderTestData.BuildShortHeader(0x00, destinationConnectionId);
    }

    internal static QuicConnectionPathIdentity CreatePathIdentity(
        string remoteAddress = "203.0.113.10",
        string localAddress = "192.0.2.10",
        int remotePort = 44330,
        int localPort = 4433)
    {
        return new QuicConnectionPathIdentity(remoteAddress, localAddress, remotePort, localPort);
    }

    internal static async Task<byte[]> SendConformingInitialAndReceiveServerInitialAsync(
        byte[] clientInitialPacket,
        byte[] expectedClientSourceConnectionId)
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        clientSocket.Connect(listenEndPoint);

        await using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            (_, _, _) => ValueTask.FromResult(QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
            listenBacklog: 1);

        _ = listenerHost.RunAsync();
        await Task.Yield();

        int bytesSent = clientSocket.Send(clientInitialPacket);
        Assert.Equal(clientInitialPacket.Length, bytesSent);

        byte[] responseBuffer = new byte[4096];
        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(responseBuffer.AsMemory(), SocketFlags.None, receiveTimeout.Token);
        Assert.True(bytesReceived > 0);

        Assert.True(QuicPacketParser.TryParseLongHeader(
            responseBuffer.AsSpan(0, bytesReceived),
            out QuicLongHeaderPacket responseHeader));
        Assert.Equal(QuicVersionNegotiation.Version1, responseHeader.Version);
        Assert.Equal(QuicLongPacketTypeBits.Initial, responseHeader.LongPacketTypeBits);
        Assert.Equal(expectedClientSourceConnectionId, responseHeader.DestinationConnectionId.ToArray());
        Assert.Equal(8, responseHeader.SourceConnectionId.Length);

        return responseBuffer.AsSpan(0, bytesReceived).ToArray();
    }

    private static byte[] BuildLongHeaderDatagram(
        int length,
        uint version,
        byte packetType,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId)
    {
        byte headerControlBits = packetType switch
        {
            QuicLongPacketTypeBits.Initial => 0x40,
            QuicLongPacketTypeBits.ZeroRtt => 0x50,
            QuicLongPacketTypeBits.Handshake => 0x60,
            QuicLongPacketTypeBits.Retry => 0x70,
            _ => 0x40,
        };

        byte[] datagram = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version,
            destinationConnectionId,
            sourceConnectionId,
            []);

        Assert.True(datagram.Length <= length);
        Array.Resize(ref datagram, length);
        return datagram;
    }
}

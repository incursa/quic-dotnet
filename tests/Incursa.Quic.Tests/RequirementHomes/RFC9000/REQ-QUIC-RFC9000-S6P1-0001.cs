using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
public sealed class REQ_QUIC_RFC9000_S6P1_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0002">An endpoint MUST NOT send a Version Negotiation packet in response to receiving a Version Negotiation packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldSendVersionNegotiation_RequiresAnUnsupportedClientVersionAndServerSupport()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.VersionNegotiationVersion,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            []));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatVersionNegotiationResponse_FormatsEchoedConnectionIdsAndSupportedVersions()
    {
        byte[] destination = new byte[64];
        byte[] clientDestinationConnectionId = [0x01, 0x02];
        byte[] clientSourceConnectionId = [0x03, 0x04, 0x05];
        uint[] serverSupportedVersions = [QuicVersionNegotiation.Version1, 0x11223344];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId,
            clientSourceConnectionId,
            serverSupportedVersions,
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
        Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        Assert.Equal(serverSupportedVersions.Length, packet.SupportedVersionCount);
        Assert.True(packet.ContainsSupportedVersion(QuicVersionNegotiation.Version1));
        Assert.True(packet.ContainsSupportedVersion(0x11223344));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatVersionNegotiationResponse_RejectsTheReservedVersionNumberInTheAdvertisedList()
    {
        byte[] destination = new byte[64];

        Assert.False(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId: [0x01, 0x02],
            clientSourceConnectionId: [0x03],
            serverSupportedVersions: [QuicVersionNegotiation.VersionNegotiationVersion],
            destination,
            out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2P2-0001">If a server receives a packet that indicates an unsupported version and the packet is large enough to initiate a new connection for any supported version, the server SHOULD send a Version Negotiation packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2P2-0004">Servers SHOULD respond with a Version Negotiation packet, provided that the datagram is sufficiently long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public async Task ListenerRespondsToTheInteropRunnerWaitForItProbeWithVersionNegotiation()
    {
        // Regression from the preserved 2026-04-22 server-role quic-go handshake runner runs:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-103812560-server-nginx\
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-104917737-server-nginx\
        //   runner-logs\nginx_quic-go\handshake\output.txt
        // The external runner's wait-for-it-quic probe sends a 1200-byte long-header packet
        // with version 0x57414954 and waits for a Version Negotiation response:
        // https://raw.githubusercontent.com/quic-interop/quic-network-simulator/master/sim/wait-for-it-quic/wait-for-it.go
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("server4");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        using Socket probeSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probeSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        byte[] waitForItProbe = BuildInteropRunnerWaitForItProbe();
        await probeSocket.SendToAsync(waitForItProbe, SocketFlags.None, listenEndPoint);

        byte[] responseBuffer = new byte[1500];
        using CancellationTokenSource responseTimeout = new(TimeSpan.FromSeconds(5));
        SocketReceiveFromResult response = await probeSocket.ReceiveFromAsync(
            responseBuffer,
            SocketFlags.None,
            new IPEndPoint(IPAddress.Any, 0),
            responseTimeout.Token);

        Assert.True(
            QuicPacketParser.TryParseVersionNegotiation(
                responseBuffer.AsSpan(0, response.ReceivedBytes),
                out QuicVersionNegotiationPacket packet));
        Assert.Equal(0, packet.DestinationConnectionIdLength);
        Assert.Equal(0, packet.SourceConnectionIdLength);
        Assert.Equal(1, packet.SupportedVersionCount);
        Assert.True(packet.ContainsSupportedVersion(QuicVersionNegotiation.Version1));
    }

    private static byte[] BuildInteropRunnerWaitForItProbe()
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 0x57414954,
            destinationConnectionId: [],
            sourceConnectionId: [],
            versionSpecificData: new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 7]);
    }
}

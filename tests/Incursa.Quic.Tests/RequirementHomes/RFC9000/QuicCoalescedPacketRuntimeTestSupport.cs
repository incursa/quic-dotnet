using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

internal static class QuicCoalescedPacketRuntimeTestSupport
{
    internal static CoalescedServerFlightScenario CreateClientRuntimeWithCoalescedServerFlight()
    {
        byte[] initialDestinationConnectionId =
        [
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ];
        byte[] clientSourceConnectionId =
        [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        ];
        byte[] serverSourceConnectionId =
        [
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        ];

        QuicConnectionPathIdentity pathIdentity = new(
            "203.0.113.10",
            "198.51.100.20",
            443,
            12345);

        QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            remoteCertificateValidationCallback: static (_, _, _, errors) =>
                errors == SslPolicyErrors.None || errors == SslPolicyErrors.RemoteCertificateChainErrors,
            clientAuthenticationOptions: new SslClientAuthenticationOptions
            {
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            },
            tlsRole: QuicTlsRole.Client);

        Assert.True(clientRuntime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        Assert.True(clientRuntime.TrySetBootstrapOutboundPath(pathIdentity));
        Assert.True(clientRuntime.TrySetHandshakeSourceConnectionId(clientSourceConnectionId));

        QuicTransportParameters clientTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(clientSourceConnectionId);
        QuicConnectionTransitionResult clientBootstrap = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 1,
                LocalTransportParameters: clientTransportParameters),
            nowTicks: 1);

        Assert.True(clientBootstrap.StateChanged);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams = clientBootstrap.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(clientInitialDatagrams);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        QuicServerConnectionSettings serverSettings = QuicServerConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate),
            parameterName: "serverOptions",
            listenerApplicationProtocols: [SslApplicationProtocol.Http3]);

        QuicConnectionRuntime serverRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);
        Assert.True(serverRuntime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        Assert.True(serverRuntime.TrySetHandshakeDestinationConnectionId(clientSourceConnectionId));
        Assert.True(serverRuntime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId));
        Assert.True(serverRuntime.TryConfigureServerAuthenticationMaterial(
            serverSettings.ServerLeafCertificateDer,
            serverSettings.ServerLeafSigningPrivateKey));

        QuicTransportParameters serverTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(serverSourceConnectionId);
        Assert.True(serverRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 1,
                LocalTransportParameters: serverTransportParameters),
            nowTicks: 1).StateChanged);

        byte[]? initialPacket = null;
        byte[]? handshakePacket = null;
        long nowTicks = 2;
        foreach (QuicConnectionSendDatagramEffect clientInitialDatagram in clientInitialDatagrams)
        {
            QuicConnectionTransitionResult serverResult = serverRuntime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: nowTicks,
                    PathIdentity: pathIdentity,
                    Datagram: clientInitialDatagram.Datagram),
                nowTicks: nowTicks);

            initialPacket ??= TryExtractFirstPacketBySpace(serverResult.Effects, QuicPacketNumberSpace.Initial);
            handshakePacket ??= TryExtractFirstPacketBySpace(serverResult.Effects, QuicPacketNumberSpace.Handshake);
            if (initialPacket is not null && handshakePacket is not null)
            {
                break;
            }

            nowTicks++;
        }

        Assert.NotNull(initialPacket);
        Assert.NotNull(handshakePacket);

        return new CoalescedServerFlightScenario(
            clientRuntime,
            serverRuntime,
            pathIdentity,
            initialDestinationConnectionId,
            [.. initialPacket!, .. handshakePacket!],
            initialPacket!,
            handshakePacket!);
    }

    private static byte[]? TryExtractFirstPacketBySpace(
        IEnumerable<QuicConnectionEffect> effects,
        QuicPacketNumberSpace packetNumberSpace)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            int packetOffset = 0;
            while (packetOffset < sendEffect.Datagram.Length)
            {
                ReadOnlyMemory<byte> remainingDatagram = sendEffect.Datagram[packetOffset..];
                Assert.True(QuicPacketParser.TryGetPacketLength(remainingDatagram.Span, out int packetLength));
                ReadOnlyMemory<byte> packet = remainingDatagram[..packetLength];
                if (QuicPacketParser.TryGetPacketNumberSpace(packet.Span, out QuicPacketNumberSpace observedPacketNumberSpace)
                    && observedPacketNumberSpace == packetNumberSpace)
                {
                    return packet.ToArray();
                }

                packetOffset += packetLength;
            }
        }

        return null;
    }

    internal sealed record CoalescedServerFlightScenario(
        QuicConnectionRuntime ClientRuntime,
        QuicConnectionRuntime ServerRuntime,
        QuicConnectionPathIdentity PathIdentity,
        byte[] InitialDestinationConnectionId,
        byte[] CoalescedDatagram,
        byte[] InitialPacket,
        byte[] HandshakePacket);
}

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;

namespace Incursa.Quic.Tests;

internal static class QuicLoopbackEstablishmentTestSupport
{
    internal static X509Certificate2 CreateServerCertificate()
    {
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=Incursa.Quic Loopback Establishment Test",
            leafKey,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    internal static QuicServerConnectionOptions CreateSupportedServerOptions(X509Certificate2 serverCertificate)
    {
        ArgumentNullException.ThrowIfNull(serverCertificate);

        return new QuicServerConnectionOptions
        {
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ServerCertificate = serverCertificate,
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            },
        };
    }

    internal static QuicClientConnectionOptions CreateSupportedClientOptions(IPEndPoint remoteEndPoint)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = remoteEndPoint,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                RemoteCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.RemoteCertificateChainErrors,
            },
        };
    }

    internal static QuicTransportParameters CreateSupportedTransportParameters(ReadOnlySpan<byte> initialSourceConnectionId)
    {
        if (initialSourceConnectionId.IsEmpty)
        {
            throw new ArgumentException("The initial source connection ID must not be empty.", nameof(initialSourceConnectionId));
        }

        return new QuicTransportParameters
        {
            InitialMaxData = 1,
            InitialMaxStreamDataBidiLocal = 1,
            InitialMaxStreamDataBidiRemote = 1,
            InitialMaxStreamDataUni = 1,
            InitialMaxStreamsBidi = 1,
            InitialMaxStreamsUni = 1,
            ActiveConnectionIdLimit = 2,
            InitialSourceConnectionId = initialSourceConnectionId.ToArray(),
        };
    }

    internal static IPEndPoint GetUnusedLoopbackEndPoint()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (IPEndPoint)socket.LocalEndPoint!;
    }

    internal static string DescribeConnection(QuicConnection? connection)
    {
        if (connection is null)
        {
            return "<null>";
        }

        FieldInfo? runtimeField = typeof(QuicConnection).GetField("runtime", BindingFlags.NonPublic | BindingFlags.Instance);
        if (runtimeField?.GetValue(connection) is not QuicConnectionRuntime runtime)
        {
            return "<runtime unavailable>";
        }

        QuicTransportTlsBridgeState tlsState = runtime.TlsState;
        QuicConnectionTerminalState? terminalState = runtime.TerminalState;
        string handshakeFlowDescription = DescribeHandshakeFlow(runtime);
        string amplificationDescription = runtime.ActivePath is null
            ? "<null>"
            : runtime.ActivePath.Value.AmplificationState.RemainingSendBudget.ToString();
        return string.Join(
            "; ",
            [
                $"Phase={runtime.Phase}",
                $"PeerHandshakeTranscriptCompleted={runtime.PeerHandshakeTranscriptCompleted}",
                $"TerminalState={(terminalState is null ? "<null>" : terminalState.Value.Close.ReasonPhrase ?? terminalState.Value.Origin.ToString())}",
                $"ActivePath={(runtime.ActivePath is null ? "<null>" : runtime.ActivePath.Value.Identity.RemoteAddress + ":" + runtime.ActivePath.Value.Identity.RemotePort)}",
                $"ActivePathSendBudget={amplificationDescription}",
                $"LocalTP={(tlsState.LocalTransportParameters is null ? "<null>" : "set")}",
                $"PeerTP={(tlsState.PeerTransportParameters is null ? "<null>" : "set")}",
                $"InitialIngress={tlsState.InitialIngressCryptoBuffer.BufferedBytes}",
                $"InitialEgress={tlsState.InitialEgressCryptoBuffer.BufferedBytes}",
                $"HandshakeIngress={tlsState.HandshakeIngressCryptoBuffer.BufferedBytes}",
                $"HandshakeEgress={tlsState.HandshakeEgressCryptoBuffer.BufferedBytes}",
                $"HandshakeFlow={handshakeFlowDescription}",
                $"SentPackets={runtime.SendRuntime.SentPackets.Count}",
                $"PendingRetransmissions={runtime.SendRuntime.PendingRetransmissionCount}",
            ]);
    }

    internal static string DescribeClientHost(QuicClientConnectionHost? host)
    {
        if (host is null)
        {
            return "<null>";
        }

        FieldInfo? connectionField = typeof(QuicClientConnectionHost).GetField("connection", BindingFlags.NonPublic | BindingFlags.Instance);
        if (connectionField?.GetValue(host) is not QuicConnection connection)
        {
            return "<connection unavailable>";
        }

        return DescribeConnection(connection);
    }

    private static string DescribeHandshakeFlow(QuicConnectionRuntime runtime)
    {
        FieldInfo? handshakeFlowField = typeof(QuicConnectionRuntime).GetField("handshakeFlowCoordinator", BindingFlags.NonPublic | BindingFlags.Instance);
        if (handshakeFlowField?.GetValue(runtime) is not QuicHandshakeFlowCoordinator handshakeFlow)
        {
            return "<unavailable>";
        }

        FieldInfo? initialDestinationField = typeof(QuicHandshakeFlowCoordinator).GetField("initialDestinationConnectionId", BindingFlags.NonPublic | BindingFlags.Instance);
        FieldInfo? destinationField = typeof(QuicHandshakeFlowCoordinator).GetField("destinationConnectionId", BindingFlags.NonPublic | BindingFlags.Instance);
        FieldInfo? sourceField = typeof(QuicHandshakeFlowCoordinator).GetField("sourceConnectionId", BindingFlags.NonPublic | BindingFlags.Instance);
        FieldInfo? nextPacketNumberField = typeof(QuicHandshakeFlowCoordinator).GetField("nextPacketNumber", BindingFlags.NonPublic | BindingFlags.Instance);

        static string FormatConnectionId(FieldInfo? field, object target)
        {
            return field?.GetValue(target) is byte[] value
                ? string.Join(string.Empty, value.Select(static b => b.ToString("X2")))
                : "<null>";
        }

        string initialDestination = FormatConnectionId(initialDestinationField, handshakeFlow);
        string destination = FormatConnectionId(destinationField, handshakeFlow);
        string source = FormatConnectionId(sourceField, handshakeFlow);
        string nextPacketNumber = nextPacketNumberField?.GetValue(handshakeFlow)?.ToString() ?? "<null>";

        return $"InitialDcid={initialDestination}, Dcid={destination}, Scid={source}, NextPn={nextPacketNumber}";
    }
}

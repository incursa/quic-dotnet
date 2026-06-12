// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#pragma warning disable CA1416

namespace Incursa.Quic.Tests;

internal static class QuicLoopbackEstablishmentTestSupport
{
    private const int PreferredLoopbackPortStart = 20_000;
    private const int PreferredLoopbackPortEnd = 30_000;
    private static readonly ConcurrentDictionary<int, byte> UsedLoopbackPorts = new();

    internal static X509Certificate2 CreateServerCertificate(string? dnsName = null)
    {
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            dnsName is null
                ? "CN=Incursa.Quic Loopback Establishment Test"
                : $"CN={dnsName}",
            leafKey,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (!string.IsNullOrEmpty(dnsName))
        {
            SubjectAlternativeNameBuilder subjectAlternativeName = new();
            subjectAlternativeName.AddDnsName(dnsName);
            request.CertificateExtensions.Add(subjectAlternativeName.Build());
        }

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

    internal static QuicClientConnectionOptions CreateSupportedClientOptions(
        IPEndPoint remoteEndPoint,
        string? targetHost = null,
        X509Certificate2? trustedServerCertificate = null,
        CipherSuitesPolicy? cipherSuitesPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        SslClientAuthenticationOptions clientAuthenticationOptions = new()
        {
            AllowRenegotiation = false,
            AllowTlsResume = true,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            EnabledSslProtocols = SslProtocols.Tls13,
            EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            CipherSuitesPolicy = cipherSuitesPolicy,
        };

        if (trustedServerCertificate is not null)
        {
            clientAuthenticationOptions.TargetHost = targetHost ?? "localhost";
            clientAuthenticationOptions.CertificateChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck,
                TrustMode = X509ChainTrustMode.CustomRootTrust,
            };
            clientAuthenticationOptions.CertificateChainPolicy.CustomTrustStore.Add(
                X509CertificateLoader.LoadCertificate(trustedServerCertificate.RawData));
        }
        else
        {
            if (!string.IsNullOrEmpty(targetHost))
            {
                clientAuthenticationOptions.TargetHost = targetHost;
            }

            clientAuthenticationOptions.RemoteCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.RemoteCertificateChainErrors;
        }

        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = remoteEndPoint,
            ClientAuthenticationOptions = clientAuthenticationOptions,
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
        for (int attempt = 0; attempt <= PreferredLoopbackPortEnd - PreferredLoopbackPortStart; attempt++)
        {
            int selectedPort = RandomNumberGenerator.GetInt32(PreferredLoopbackPortStart, PreferredLoopbackPortEnd + 1);
            if (!UsedLoopbackPorts.TryAdd(selectedPort, 0))
            {
                continue;
            }

            using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.Bind(new IPEndPoint(IPAddress.Loopback, selectedPort));
                return (IPEndPoint)socket.LocalEndPoint!;
            }
            catch (SocketException)
            {
                UsedLoopbackPorts.TryRemove(selectedPort, out _);
                continue;
            }
        }

        for (int attempt = 0; attempt < 100; attempt++)
        {
            using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            IPEndPoint selectedEndPoint = (IPEndPoint)socket.LocalEndPoint!;
            if (UsedLoopbackPorts.TryAdd(selectedEndPoint.Port, 0))
            {
                return selectedEndPoint;
            }
        }

        throw new InvalidOperationException("Unable to allocate a loopback UDP port that has not already been used by this test process.");
    }

    internal static string DescribeConnection(QuicConnection? connection)
    {
        if (connection is null)
        {
            return "<null>";
        }

        QuicConnectionRuntime runtime = connection.Runtime;

        QuicTransportTlsBridgeState tlsState = runtime.TlsState;
        QuicConnectionTerminalState? terminalState = runtime.TerminalState;
        string handshakeFlowDescription = DescribeHandshakeFlow(runtime.HandshakeFlowCoordinator);
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
                $"StagedPeerTP={(tlsState.StagedPeerTransportParameters is null ? "<null>" : "set")}",
                $"HandshakePhase={tlsState.HandshakeTranscriptPhase}",
                $"SelectedCipher={(tlsState.SelectedCipherSuite is null ? "<null>" : tlsState.SelectedCipherSuite.ToString())}",
                $"InitialKeys={tlsState.InitialKeysAvailable}",
                $"HandshakeKeys={tlsState.HandshakeKeysAvailable}",
                $"OneRttKeys={tlsState.OneRttKeysAvailable}",
                $"HandshakeOpenTP={(tlsState.HandshakeOpenPacketProtectionMaterial is null ? "<null>" : "set")}",
                $"HandshakeProtectTP={(tlsState.HandshakeProtectPacketProtectionMaterial is null ? "<null>" : "set")}",
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

        QuicConnection connection = host.Connection;

        return DescribeConnection(connection);
    }

    private static string DescribeHandshakeFlow(QuicHandshakeFlowCoordinator handshakeFlow)
    {
        static string FormatConnectionId(ReadOnlyMemory<byte> value)
        {
            return value.IsEmpty ? "<null>" : Convert.ToHexString(value.Span);
        }

        string initialDestination = FormatConnectionId(handshakeFlow.InitialDestinationConnectionId);
        string destination = FormatConnectionId(handshakeFlow.DestinationConnectionId);
        string source = FormatConnectionId(handshakeFlow.SourceConnectionId);
        string nextPacketNumber = handshakeFlow.NextPacketNumber.ToString();

        return $"InitialDcid={initialDestination}, Dcid={destination}, Scid={source}, NextPn={nextPacketNumber}";
    }
}

#pragma warning restore CA1416

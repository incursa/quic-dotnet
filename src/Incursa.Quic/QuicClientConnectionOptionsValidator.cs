using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic;

internal static class QuicClientConnectionOptionsValidator
{
    public static QuicClientConnectionSettings Capture(
        QuicClientConnectionOptions options,
        string parameterName,
        QuicClientCertificatePolicySnapshot? clientCertificatePolicySnapshot = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.RemoteEndPoint is null)
        {
            throw new ArgumentNullException($"{parameterName}.{nameof(QuicClientConnectionOptions.RemoteEndPoint)}");
        }

        if (options.RemoteEndPoint is not IPEndPoint remoteEndPoint)
        {
            throw new NotSupportedException("Only IPEndPoint remote endpoints are supported by this client-entry slice.");
        }

        SslClientAuthenticationOptions authenticationOptions = options.ClientAuthenticationOptions
            ?? throw new ArgumentNullException($"{parameterName}.{nameof(QuicClientConnectionOptions.ClientAuthenticationOptions)}");
        QuicClientCertificatePolicySnapshot? capturedCertificatePolicySnapshot =
            clientCertificatePolicySnapshot ?? CapturePeerCertificatePolicySnapshot(options.PeerCertificatePolicy);

        if (authenticationOptions.ApplicationProtocols is null)
        {
            throw new ArgumentNullException($"{parameterName}.{nameof(QuicClientConnectionOptions.ClientAuthenticationOptions)}.{nameof(SslClientAuthenticationOptions.ApplicationProtocols)}");
        }

        if (authenticationOptions.ApplicationProtocols.Count == 0)
        {
            throw new ArgumentException("At least one application protocol is required.", $"{parameterName}.{nameof(QuicClientConnectionOptions.ClientAuthenticationOptions)}.{nameof(SslClientAuthenticationOptions.ApplicationProtocols)}");
        }

        if (capturedCertificatePolicySnapshot is not null)
        {
            if (!string.IsNullOrEmpty(authenticationOptions.TargetHost))
            {
                throw new NotSupportedException("ClientAuthenticationOptions.TargetHost is not supported when PeerCertificatePolicy is supplied because the exact-pinning path does not use hostname validation.");
            }

            if (authenticationOptions.CertificateChainPolicy is not null)
            {
                throw new NotSupportedException("CertificateChainPolicy is not supported when PeerCertificatePolicy is supplied because the exact-pinning path does not use chain validation.");
            }

            if (authenticationOptions.CertificateRevocationCheckMode != X509RevocationMode.NoCheck)
            {
                throw new NotSupportedException("Certificate revocation checking is not supported when PeerCertificatePolicy is supplied because the exact-pinning path does not use chain validation.");
            }

            if (authenticationOptions.RemoteCertificateValidationCallback is not null)
            {
                throw new NotSupportedException("RemoteCertificateValidationCallback is not supported when PeerCertificatePolicy is supplied because the exact-pinning path does not use the standard callback-driven validation flow.");
            }
        }

        if (authenticationOptions.ClientCertificates is { Count: > 0 })
        {
            throw new NotSupportedException("Client certificates are not supported by this slice.");
        }

        if (authenticationOptions.ClientCertificateContext is not null)
        {
            throw new NotSupportedException("Client certificate contexts are not supported by this slice.");
        }

        if (authenticationOptions.LocalCertificateSelectionCallback is not null)
        {
            throw new NotSupportedException("Local certificate selection callbacks are not supported by this slice.");
        }

        if (authenticationOptions.CipherSuitesPolicy is not null)
        {
            throw new NotSupportedException("Cipher suite policies are not supported by this slice.");
        }

        if (authenticationOptions.EncryptionPolicy != EncryptionPolicy.RequireEncryption)
        {
            throw new NotSupportedException("Only EncryptionPolicy.RequireEncryption is supported by this slice.");
        }

        if (authenticationOptions.EnabledSslProtocols != SslProtocols.None
            && authenticationOptions.EnabledSslProtocols != SslProtocols.Tls13)
        {
            throw new NotSupportedException("Only TLS 1.3 is supported by this slice.");
        }

        if (authenticationOptions.AllowRenegotiation)
        {
            throw new NotSupportedException("Renegotiation settings are not supported by this slice.");
        }

        if (!authenticationOptions.AllowTlsResume)
        {
            throw new NotSupportedException("TLS resumption settings are not supported by this slice.");
        }

        if (!authenticationOptions.AllowRsaPkcs1Padding || !authenticationOptions.AllowRsaPssPadding)
        {
            throw new NotSupportedException("RSA padding overrides are not supported by this slice.");
        }

        return new QuicClientConnectionSettings(
            CaptureOptions(options, authenticationOptions),
            CloneEndPoint(remoteEndPoint),
            options.LocalEndPoint is null ? null : CloneEndPoint(options.LocalEndPoint),
            capturedCertificatePolicySnapshot);
    }

    private static QuicClientConnectionOptions CaptureOptions(
        QuicClientConnectionOptions source,
        SslClientAuthenticationOptions authenticationOptions)
    {
        QuicReceiveWindowSizes windows = source.InitialReceiveWindowSizes;
        List<SslApplicationProtocol> applicationProtocols = authenticationOptions.ApplicationProtocols is { Count: > 0 } protocols
            ? [.. protocols]
            : throw new ArgumentNullException($"{nameof(source)}.{nameof(QuicClientConnectionOptions.ClientAuthenticationOptions)}.{nameof(SslClientAuthenticationOptions.ApplicationProtocols)}");

        return new QuicClientConnectionOptions
        {
            DefaultCloseErrorCode = source.DefaultCloseErrorCode,
            DefaultStreamErrorCode = source.DefaultStreamErrorCode,
            HandshakeTimeout = source.HandshakeTimeout,
            IdleTimeout = source.IdleTimeout,
            KeepAliveInterval = source.KeepAliveInterval,
            MaxInboundBidirectionalStreams = source.MaxInboundBidirectionalStreams,
            MaxInboundUnidirectionalStreams = source.MaxInboundUnidirectionalStreams,
            StreamCapacityCallback = source.StreamCapacityCallback,
            InitialReceiveWindowSizes = new QuicReceiveWindowSizes
            {
                Connection = windows.Connection,
                LocallyInitiatedBidirectionalStream = windows.LocallyInitiatedBidirectionalStream,
                RemotelyInitiatedBidirectionalStream = windows.RemotelyInitiatedBidirectionalStream,
                UnidirectionalStream = windows.UnidirectionalStream,
            },
            LocalEndPoint = source.LocalEndPoint is null ? null : CloneEndPoint(source.LocalEndPoint),
            PeerCertificatePolicy = ClonePeerCertificatePolicy(source.PeerCertificatePolicy),
            RemoteEndPoint = CloneEndPoint((IPEndPoint)source.RemoteEndPoint),
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = authenticationOptions.AllowRenegotiation,
                AllowTlsResume = authenticationOptions.AllowTlsResume,
                ApplicationProtocols = applicationProtocols,
                CertificateChainPolicy = authenticationOptions.CertificateChainPolicy?.Clone(),
                CertificateRevocationCheckMode = authenticationOptions.CertificateRevocationCheckMode,
                EnabledSslProtocols = authenticationOptions.EnabledSslProtocols,
                EncryptionPolicy = authenticationOptions.EncryptionPolicy,
                TargetHost = authenticationOptions.TargetHost,
                RemoteCertificateValidationCallback = authenticationOptions.RemoteCertificateValidationCallback,
            },
        };
    }

    private static QuicClientCertificatePolicySnapshot? CapturePeerCertificatePolicySnapshot(QuicPeerCertificatePolicy? source)
    {
        return source is null
            ? null
            : new QuicClientCertificatePolicySnapshot(
                source.ExactPeerLeafCertificateDer,
                source.ExplicitTrustMaterialSha256);
    }

    private static QuicPeerCertificatePolicy? ClonePeerCertificatePolicy(QuicPeerCertificatePolicy? source)
    {
        return source is null
            ? null
            : new QuicPeerCertificatePolicy
            {
                ExactPeerLeafCertificateDer = source.ExactPeerLeafCertificateDer,
                ExplicitTrustMaterialSha256 = source.ExplicitTrustMaterialSha256,
            };
    }

    private static IPEndPoint CloneEndPoint(IPEndPoint endPoint)
    {
        ArgumentNullException.ThrowIfNull(endPoint);
        return new IPEndPoint(endPoint.Address, endPoint.Port);
    }
}

internal sealed record QuicClientConnectionSettings(
    QuicClientConnectionOptions Options,
    IPEndPoint RemoteEndPoint,
    IPEndPoint? LocalEndPoint,
    QuicClientCertificatePolicySnapshot? ClientCertificatePolicySnapshot = null);

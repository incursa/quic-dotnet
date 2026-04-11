using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic;

internal static class QuicClientConnectionOptionsValidator
{
    public static QuicClientConnectionSettings Capture(QuicClientConnectionOptions options, string parameterName)
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

        if (authenticationOptions.ApplicationProtocols is null)
        {
            throw new ArgumentNullException($"{parameterName}.{nameof(QuicClientConnectionOptions.ClientAuthenticationOptions)}.{nameof(SslClientAuthenticationOptions.ApplicationProtocols)}");
        }

        if (authenticationOptions.ApplicationProtocols.Count == 0)
        {
            throw new ArgumentException("At least one application protocol is required.", $"{parameterName}.{nameof(QuicClientConnectionOptions.ClientAuthenticationOptions)}.{nameof(SslClientAuthenticationOptions.ApplicationProtocols)}");
        }

        if (authenticationOptions.RemoteCertificateValidationCallback is null)
        {
            throw new NotSupportedException("ClientAuthenticationOptions.RemoteCertificateValidationCallback is required because this slice does not yet support trust-store or hostname validation.");
        }

        if (!string.IsNullOrEmpty(authenticationOptions.TargetHost))
        {
            throw new NotSupportedException("ClientAuthenticationOptions.TargetHost is not supported by this slice because SNI and hostname validation are not implemented yet.");
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

        if (authenticationOptions.CertificateChainPolicy is not null)
        {
            throw new NotSupportedException("Certificate chain policies are not supported by this slice.");
        }

        if (authenticationOptions.CipherSuitesPolicy is not null)
        {
            throw new NotSupportedException("Cipher suite policies are not supported by this slice.");
        }

        if (authenticationOptions.CertificateRevocationCheckMode != X509RevocationMode.NoCheck)
        {
            throw new NotSupportedException("Certificate revocation checking is not supported by this slice.");
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
            options.LocalEndPoint is null ? null : CloneEndPoint(options.LocalEndPoint));
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
            RemoteEndPoint = CloneEndPoint((IPEndPoint)source.RemoteEndPoint),
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = authenticationOptions.AllowRenegotiation,
                AllowTlsResume = authenticationOptions.AllowTlsResume,
                ApplicationProtocols = applicationProtocols,
                CertificateRevocationCheckMode = authenticationOptions.CertificateRevocationCheckMode,
                EnabledSslProtocols = authenticationOptions.EnabledSslProtocols,
                EncryptionPolicy = authenticationOptions.EncryptionPolicy,
                RemoteCertificateValidationCallback = authenticationOptions.RemoteCertificateValidationCallback,
            },
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
    IPEndPoint? LocalEndPoint);

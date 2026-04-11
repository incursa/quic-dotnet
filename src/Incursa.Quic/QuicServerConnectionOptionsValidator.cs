using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic;

internal static class QuicServerConnectionOptionsValidator
{
    private const int EcdsaP256KeySize = 256;

    public static QuicServerConnectionSettings Capture(
        QuicServerConnectionOptions options,
        string parameterName,
        IReadOnlyList<SslApplicationProtocol> listenerApplicationProtocols)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(listenerApplicationProtocols);

        SslServerAuthenticationOptions authenticationOptions = options.ServerAuthenticationOptions
            ?? throw new ArgumentNullException($"{parameterName}.{nameof(QuicServerConnectionOptions.ServerAuthenticationOptions)}");

        if (authenticationOptions.ApplicationProtocols is null)
        {
            throw new ArgumentNullException($"{parameterName}.{nameof(QuicServerConnectionOptions.ServerAuthenticationOptions)}.{nameof(SslServerAuthenticationOptions.ApplicationProtocols)}");
        }

        if (authenticationOptions.ApplicationProtocols.Count == 0)
        {
            throw new ArgumentException(
                "At least one application protocol is required.",
                $"{parameterName}.{nameof(QuicServerConnectionOptions.ServerAuthenticationOptions)}.{nameof(SslServerAuthenticationOptions.ApplicationProtocols)}");
        }

        if (!authenticationOptions.ApplicationProtocols.SequenceEqual(listenerApplicationProtocols))
        {
            throw new NotSupportedException("Server authentication application protocols must match the listener application protocols for this slice.");
        }

        if (authenticationOptions.ServerCertificate is not X509Certificate2 serverCertificate)
        {
            throw new NotSupportedException("ServerAuthenticationOptions.ServerCertificate must be an X509Certificate2 with an ECDsa P-256 private key for this slice.");
        }

        if (authenticationOptions.ServerCertificateSelectionCallback is not null)
        {
            throw new NotSupportedException("Server certificate selection callbacks are not supported by this slice.");
        }

        if (authenticationOptions.ClientCertificateRequired)
        {
            throw new NotSupportedException("Client certificate authentication is not supported by this slice.");
        }

        if (authenticationOptions.CipherSuitesPolicy is not null)
        {
            throw new NotSupportedException("Cipher suite policies are not supported by this slice.");
        }

        if (authenticationOptions.EnabledSslProtocols != SslProtocols.None
            && authenticationOptions.EnabledSslProtocols != SslProtocols.Tls13)
        {
            throw new NotSupportedException("Only TLS 1.3 is supported by this slice.");
        }

        if (authenticationOptions.EncryptionPolicy != EncryptionPolicy.RequireEncryption)
        {
            throw new NotSupportedException("Only EncryptionPolicy.RequireEncryption is supported by this slice.");
        }

        using ECDsa? signingKey = serverCertificate.GetECDsaPrivateKey();
        if (signingKey is null || signingKey.KeySize != EcdsaP256KeySize)
        {
            throw new NotSupportedException("ServerAuthenticationOptions.ServerCertificate must carry an ECDsa P-256 private key for this slice.");
        }

        byte[] certificateDer = serverCertificate.Export(X509ContentType.Cert);
        ECParameters privateParameters;
        try
        {
            privateParameters = signingKey.ExportParameters(true);
        }
        catch (CryptographicException ex)
        {
            throw new NotSupportedException("ServerAuthenticationOptions.ServerCertificate must carry an exportable ECDsa P-256 private key for this slice.", ex);
        }

        if (privateParameters.D is null || privateParameters.Q.X is null || privateParameters.Q.Y is null)
        {
            throw new NotSupportedException("ServerAuthenticationOptions.ServerCertificate must carry a complete ECDsa P-256 private key for this slice.");
        }

        return new QuicServerConnectionSettings(
            options,
            certificateDer,
            privateParameters.D.ToArray());
    }
}

internal sealed record QuicServerConnectionSettings(
    QuicServerConnectionOptions Options,
    byte[] ServerLeafCertificateDer,
    byte[] ServerLeafSigningPrivateKey);

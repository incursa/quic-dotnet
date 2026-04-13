using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0126")]
public sealed class REQ_QUIC_CRT_0126
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleEmitsCertificateRequestAndHonorsStandaloneRevocationModeThroughTheCallbackSeam()
    {
        byte[] serverHandshakePrivateKey = CreateScalar(0x22);
        byte[] serverSigningPrivateKey = CreateScalar(0x44);
        byte[] clientHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa serverCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        serverCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = serverSigningPrivateKey,
        });

        byte[] serverLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(serverCertificateKey);

        using ECDsa clientCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] clientLeafCertificateScalar = CreateScalar(0x66);
        clientCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = clientLeafCertificateScalar,
        });

        byte[] clientLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(clientCertificateKey);

        bool callbackInvoked = false;
        byte[]? observedCertificateDer = null;
        SslPolicyErrors observedErrors = default;
        X509RevocationMode observedRevocationMode = default;
        X509RevocationFlag observedRevocationFlag = default;
        int observedApplicationPolicyCount = 0;

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: serverHandshakePrivateKey,
            localServerLeafCertificateDer: serverLeafCertificateDer,
            localServerLeafSigningPrivateKey: serverSigningPrivateKey);

        Assert.True(driver.TryConfigureServerAuthenticationMaterial(
            serverLeafCertificateDer,
            serverSigningPrivateKey,
            clientCertificateRequired: true,
            serverClientCertificateRevocationCheckMode: X509RevocationMode.Offline,
            serverRemoteCertificateValidationCallback: (_, certificate, chain, errors) =>
            {
                callbackInvoked = true;
                observedCertificateDer = certificate?.GetRawCertData();
                observedErrors = errors;
                Assert.NotNull(chain);
                observedRevocationMode = chain!.ChainPolicy.RevocationMode;
                observedRevocationFlag = chain.ChainPolicy.RevocationFlag;
                observedApplicationPolicyCount = chain.ChainPolicy.ApplicationPolicy.Count;
                return true;
            }));

        Assert.Single(driver.StartHandshake(localTransportParameters));

        QuicTlsKeySchedule clientHelloSchedule = new(clientHandshakePrivateKey);
        Assert.True(clientHelloSchedule.TryCreateClientHello(peerTransportParameters, out byte[] clientHello));

        IReadOnlyList<QuicTlsStateUpdate> serverUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHello);

        Assert.Contains(
            serverUpdates,
            update => update.Kind == QuicTlsUpdateKind.TranscriptProgressed
                && update.HandshakeMessageType == QuicTlsHandshakeMessageType.ClientHello);

        QuicTlsStateUpdate serverCertificateRequestUpdate = Assert.Single(
            serverUpdates,
            update => update.Kind == QuicTlsUpdateKind.CryptoDataAvailable
                && ParseHandshakeMessageType(update.CryptoData.Span) == QuicTlsHandshakeMessageType.CertificateRequest);
        Assert.True(QuicTlsCertificateVerifyTestSupport.CreateCertificateRequestTranscript().AsSpan().SequenceEqual(
            serverCertificateRequestUpdate.CryptoData.Span));

        byte[] clientCertificateTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(clientLeafCertificateDer);
        byte[] clientCertificateVerifyTranscript = CreateClientCertificateVerifyTranscript(
            clientHello,
            serverUpdates,
            clientCertificateTranscript,
            clientCertificateKey);

        IReadOnlyList<QuicTlsStateUpdate> certificateUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientCertificateTranscript);
        Assert.Single(certificateUpdates);
        Assert.Equal(QuicTlsHandshakeMessageType.Certificate, certificateUpdates[0].HandshakeMessageType);

        IReadOnlyList<QuicTlsStateUpdate> certificateVerifyUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientCertificateVerifyTranscript);
        Assert.Contains(
            certificateVerifyUpdates,
            update => update.Kind == QuicTlsUpdateKind.TranscriptProgressed
                && update.HandshakeMessageType == QuicTlsHandshakeMessageType.CertificateVerify);
        Assert.Contains(certificateVerifyUpdates, update => update.Kind == QuicTlsUpdateKind.PeerCertificateVerifyVerified);
        Assert.Contains(certificateVerifyUpdates, update => update.Kind == QuicTlsUpdateKind.PeerCertificatePolicyAccepted);
        Assert.True(callbackInvoked);
        Assert.NotNull(observedCertificateDer);
        Assert.Equal(clientLeafCertificateDer, observedCertificateDer);
        Assert.Equal(SslPolicyErrors.RemoteCertificateChainErrors, observedErrors);
        Assert.Equal(X509RevocationMode.Offline, observedRevocationMode);
        Assert.Equal(X509RevocationFlag.ExcludeRoot, observedRevocationFlag);
        Assert.Equal(1, observedApplicationPolicyCount);
        Assert.True(driver.State.PeerCertificatePolicyAccepted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerConnectionOptionsValidatorRejectsStandaloneRevocationModeWithoutClientCertificateRequired()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        QuicServerConnectionOptions options = new()
        {
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ServerCertificate = serverCertificate,
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                CertificateRevocationCheckMode = X509RevocationMode.Online,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            },
        };

        Assert.Throws<NotSupportedException>(() => QuicServerConnectionOptionsValidator.Capture(
            options,
            nameof(options),
            [SslApplicationProtocol.Http3]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerConnectionOptionsValidatorRejectsClientCertificateRequiredWhenChainPolicyAndStandaloneRevocationCustomizationAreCombined()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        QuicServerConnectionOptions options = new()
        {
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ServerCertificate = serverCertificate,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                CertificateChainPolicy = new X509ChainPolicy
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    RevocationMode = X509RevocationMode.NoCheck,
                },
                CertificateRevocationCheckMode = X509RevocationMode.Online,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            },
        };

        Assert.Throws<NotSupportedException>(() => QuicServerConnectionOptionsValidator.Capture(
            options,
            nameof(options),
            [SslApplicationProtocol.Http3]));
    }

    private static byte[] CreateClientCertificateVerifyTranscript(
        ReadOnlySpan<byte> clientHelloTranscript,
        IReadOnlyList<QuicTlsStateUpdate> serverFlightUpdates,
        ReadOnlySpan<byte> clientCertificateTranscript,
        ECDsa clientCertificateKey)
    {
        byte[] transcriptHash = SHA256.HashData(BuildClientCertificateVerifyTranscriptBytes(
            clientHelloTranscript,
            serverFlightUpdates,
            clientCertificateTranscript));

        return QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            clientCertificateKey,
            transcriptHash,
            useClientContext: true);
    }

    private static byte[] BuildClientCertificateVerifyTranscriptBytes(
        ReadOnlySpan<byte> clientHelloTranscript,
        IReadOnlyList<QuicTlsStateUpdate> serverFlightUpdates,
        ReadOnlySpan<byte> clientCertificateTranscript)
    {
        List<byte> transcriptBytes = new(clientHelloTranscript.Length + clientCertificateTranscript.Length);
        transcriptBytes.AddRange(clientHelloTranscript.ToArray());
        foreach (QuicTlsStateUpdate update in serverFlightUpdates)
        {
            if (update.Kind == QuicTlsUpdateKind.CryptoDataAvailable)
            {
                transcriptBytes.AddRange(update.CryptoData.ToArray());
            }
        }

        transcriptBytes.AddRange(clientCertificateTranscript.ToArray());
        return transcriptBytes.ToArray();
    }

    private static QuicTlsHandshakeMessageType ParseHandshakeMessageType(ReadOnlySpan<byte> handshakeMessageBytes)
    {
        return (QuicTlsHandshakeMessageType)handshakeMessageBytes[0];
    }

    private static QuicTransportParameters CreateServerTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreateClientTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 21,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
        };
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }
}

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0125")]
public sealed class REQ_QUIC_CRT_0125
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleEmitsCertificateRequestAndAcceptsClientCertificatePresentationWithCustomChainPolicyThroughTheCallbackSeam()
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
        X509Certificate2 trustedClientCertificate = X509CertificateLoader.LoadCertificate(clientLeafCertificateDer);

        X509ChainPolicy clientCertificateChainPolicy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        clientCertificateChainPolicy.CustomTrustStore.Add(trustedClientCertificate);

        bool callbackInvoked = false;
        byte[]? observedCertificateDer = null;
        SslPolicyErrors observedErrors = default;
        X509ChainTrustMode observedTrustMode = default;
        X509RevocationMode observedRevocationMode = default;
        int observedApplicationPolicyCount = 0;
        int observedCustomTrustStoreCount = 0;

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: serverHandshakePrivateKey,
            localServerLeafCertificateDer: serverLeafCertificateDer,
            localServerLeafSigningPrivateKey: serverSigningPrivateKey);

        Assert.True(driver.TryConfigureServerAuthenticationMaterial(
            serverLeafCertificateDer,
            serverSigningPrivateKey,
            clientCertificateRequired: true,
            serverClientCertificateChainPolicy: clientCertificateChainPolicy,
            serverRemoteCertificateValidationCallback: (_, certificate, chain, errors) =>
            {
                callbackInvoked = true;
                observedCertificateDer = certificate?.GetRawCertData();
                observedErrors = errors;
                Assert.NotNull(chain);
                observedTrustMode = chain!.ChainPolicy.TrustMode;
                observedRevocationMode = chain.ChainPolicy.RevocationMode;
                observedApplicationPolicyCount = chain.ChainPolicy.ApplicationPolicy.Count;
                observedCustomTrustStoreCount = chain.ChainPolicy.CustomTrustStore.Count;
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
        Assert.Equal(SslPolicyErrors.None, observedErrors);
        Assert.Equal(X509ChainTrustMode.CustomRootTrust, observedTrustMode);
        Assert.Equal(X509RevocationMode.NoCheck, observedRevocationMode);
        Assert.Equal(1, observedApplicationPolicyCount);
        Assert.Equal(1, observedCustomTrustStoreCount);
        Assert.True(driver.State.PeerCertificatePolicyAccepted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleRejectsClientCertificatePresentationWhenTheCustomChainPolicyDoesNotTrustThePresentedLeaf()
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

        using ECDsa trustedClientCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        trustedClientCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(0x77),
        });
        byte[] trustedClientLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(trustedClientCertificateKey);
        X509Certificate2 trustedClientCertificate = X509CertificateLoader.LoadCertificate(trustedClientLeafCertificateDer);

        using ECDsa presentedClientCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] presentedClientLeafCertificateScalar = CreateScalar(0x66);
        presentedClientCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = presentedClientLeafCertificateScalar,
        });

        byte[] presentedClientLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(presentedClientCertificateKey);

        X509ChainPolicy clientCertificateChainPolicy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        clientCertificateChainPolicy.CustomTrustStore.Add(trustedClientCertificate);

        bool callbackInvoked = false;
        SslPolicyErrors observedErrors = default;
        X509ChainTrustMode observedTrustMode = default;
        int observedApplicationPolicyCount = 0;
        int observedCustomTrustStoreCount = 0;

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: serverHandshakePrivateKey,
            localServerLeafCertificateDer: serverLeafCertificateDer,
            localServerLeafSigningPrivateKey: serverSigningPrivateKey);

        Assert.True(driver.TryConfigureServerAuthenticationMaterial(
            serverLeafCertificateDer,
            serverSigningPrivateKey,
            clientCertificateRequired: true,
            serverClientCertificateChainPolicy: clientCertificateChainPolicy,
            serverRemoteCertificateValidationCallback: (_, certificate, chain, errors) =>
            {
                callbackInvoked = true;
                observedErrors = errors;
                Assert.NotNull(certificate);
                Assert.NotNull(chain);
                observedTrustMode = chain!.ChainPolicy.TrustMode;
                observedApplicationPolicyCount = chain.ChainPolicy.ApplicationPolicy.Count;
                observedCustomTrustStoreCount = chain.ChainPolicy.CustomTrustStore.Count;
                return false;
            }));

        Assert.Single(driver.StartHandshake(localTransportParameters));

        QuicTlsKeySchedule clientHelloSchedule = new(clientHandshakePrivateKey);
        Assert.True(clientHelloSchedule.TryCreateClientHello(peerTransportParameters, out byte[] clientHello));

        IReadOnlyList<QuicTlsStateUpdate> serverUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHello);

        Assert.Contains(
            serverUpdates,
            update => update.Kind == QuicTlsUpdateKind.CryptoDataAvailable
                && ParseHandshakeMessageType(update.CryptoData.Span) == QuicTlsHandshakeMessageType.CertificateRequest);

        byte[] clientCertificateTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(presentedClientLeafCertificateDer);
        byte[] clientCertificateVerifyTranscript = CreateClientCertificateVerifyTranscript(
            clientHello,
            serverUpdates,
            clientCertificateTranscript,
            presentedClientCertificateKey);

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
        Assert.Contains(certificateVerifyUpdates, update => update.Kind == QuicTlsUpdateKind.FatalAlert);
        Assert.True(callbackInvoked);
        Assert.Equal(SslPolicyErrors.RemoteCertificateChainErrors, observedErrors);
        Assert.Equal(X509ChainTrustMode.CustomRootTrust, observedTrustMode);
        Assert.Equal(1, observedApplicationPolicyCount);
        Assert.Equal(1, observedCustomTrustStoreCount);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.PeerCertificatePolicyAccepted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerConnectionOptionsValidatorAcceptsClientCertificateRequiredWhenChainCustomizationIsSupplied()
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
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            },
        };

        QuicServerConnectionSettings settings = QuicServerConnectionOptionsValidator.Capture(
            options,
            nameof(options),
            [SslApplicationProtocol.Http3]);

        Assert.True(settings.Options.ServerAuthenticationOptions.ClientCertificateRequired);
        Assert.NotNull(settings.Options.ServerAuthenticationOptions.RemoteCertificateValidationCallback);
        Assert.NotNull(settings.Options.ServerAuthenticationOptions.CertificateChainPolicy);
        Assert.Equal(X509ChainTrustMode.CustomRootTrust, settings.Options.ServerAuthenticationOptions.CertificateChainPolicy!.TrustMode);
        Assert.Equal(X509RevocationMode.NoCheck, settings.Options.ServerAuthenticationOptions.CertificateChainPolicy.RevocationMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerConnectionOptionsValidatorRejectsCertificateChainPolicyWithoutClientCertificateRequired()
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
                CertificateChainPolicy = new X509ChainPolicy
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    RevocationMode = X509RevocationMode.NoCheck,
                },
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

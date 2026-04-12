using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0114")]
public sealed class REQ_QUIC_CRT_0114
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleEmitsLocalCertificateAfterLocalEncryptedExtensionsAtTheNextHandshakeOffset()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);
        byte[] expectedCertificateTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(localLeafCertificateDer);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer);

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.Equal(7, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[5].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[6].Kind);
        Assert.Equal(0UL, updates[1].CryptoDataOffset);
        Assert.Equal(0UL, updates[5].CryptoDataOffset);
        Assert.Equal((ulong)updates[5].CryptoData.Length, updates[6].CryptoDataOffset);
        Assert.True(expectedCertificateTranscript.AsSpan().SequenceEqual(updates[6].CryptoData.Span));

        Span<byte> surfacedHandshakeBytes = stackalloc byte[
            updates[5].CryptoData.Length
            + updates[6].CryptoData.Length];
        Assert.True(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            surfacedHandshakeBytes,
            out ulong egressOffset,
            out int bytesWritten));
        Assert.Equal(0UL, egressOffset);
        Assert.Equal(surfacedHandshakeBytes.Length, bytesWritten);

        byte[] expectedHandshakeBytes = [
            .. updates[5].CryptoData.ToArray(),
            .. updates[6].CryptoData.ToArray(),
        ];
        Assert.True(expectedHandshakeBytes.AsSpan().SequenceEqual(surfacedHandshakeBytes));

        QuicTlsTranscriptProgress clientProgress = new(QuicTlsRole.Client);
        clientProgress.AppendCryptoBytes(0, updates[1].CryptoData.Span);
        QuicTlsTranscriptStep serverHelloStep = clientProgress.Advance(QuicTlsRole.Client);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, serverHelloStep.HandshakeMessageType);

        clientProgress.AppendCryptoBytes((ulong)updates[1].CryptoData.Length, updates[5].CryptoData.Span);
        QuicTlsTranscriptStep encryptedExtensionsStep = clientProgress.Advance(QuicTlsRole.Client);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, encryptedExtensionsStep.HandshakeMessageType);

        clientProgress.AppendCryptoBytes(
            (ulong)updates[1].CryptoData.Length + (ulong)updates[5].CryptoData.Length,
            updates[6].CryptoData.Span);
        QuicTlsTranscriptStep certificateStep = clientProgress.Advance(QuicTlsRole.Client);
        Assert.Equal(QuicTlsHandshakeMessageType.Certificate, certificateStep.HandshakeMessageType);
        Assert.True(expectedCertificateTranscript.AsSpan().SequenceEqual(certificateStep.HandshakeMessageBytes.Span));

        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDoesNotEmitLocalCertificateBeforeLocalEncryptedExtensionsPrerequisitesExist()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer);

        Assert.Single(driver.StartHandshake(CreateServerTransportParameters()));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters)[..12]);

        Assert.Empty(updates);
        Assert.False(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            stackalloc byte[1],
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDoesNotEmitLocalCertificateWhenLocalCertificateMaterialIsUnavailable()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.Equal(6, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[^1].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, ParseHandshakeMessageType(updates[^1].CryptoData.Span));

        Span<byte> surfacedHandshakeBytes = stackalloc byte[updates[5].CryptoData.Length];
        Assert.True(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            surfacedHandshakeBytes,
            out ulong offset,
            out int bytesWritten));
        Assert.Equal(0UL, offset);
        Assert.Equal(surfacedHandshakeBytes.Length, bytesWritten);
        byte[] expectedHandshakeBytes = [
            .. updates[5].CryptoData.ToArray(),
        ];
        Assert.True(expectedHandshakeBytes.AsSpan().SequenceEqual(surfacedHandshakeBytes));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedLocalCertificateMaterialFailsDeterministically()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);
        byte[] malformedLocalLeafCertificateDer = localLeafCertificateDer[..^1];

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: malformedLocalLeafCertificateDer);

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.Equal(2, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[1].Kind);
        Assert.Equal((ushort)0x0032, updates[1].AlertDescription);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            stackalloc byte[1],
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnsupportedLocalCertificateMaterialFailsDeterministically()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        byte[] unsupportedLocalLeafCertificateDer = CreateRsaLeafCertificateDer();

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: unsupportedLocalLeafCertificateDer);

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.Equal(2, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[1].Kind);
        Assert.Equal((ushort)0x0032, updates[1].AlertDescription);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.HandshakeKeysAvailable);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleAppendsLocalCertificateToTheManagedTranscriptExplicitly()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);

        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Server);
        byte[] clientHello = CreateClientHelloTranscript(peerTransportParameters);

        progress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);

        QuicTlsKeySchedule schedule = new(QuicTlsRole.Server, localHandshakePrivateKey);
        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters,
            localLeafCertificateDer);

        byte[] expectedTranscript = new byte[
            clientHello.Length
            + updates[0].CryptoData.Length
            + updates[4].CryptoData.Length
            + updates[5].CryptoData.Length];
        clientHello.CopyTo(expectedTranscript, 0);
        updates[0].CryptoData.CopyTo(expectedTranscript.AsMemory(clientHello.Length));
        updates[4].CryptoData.CopyTo(expectedTranscript.AsMemory(clientHello.Length + updates[0].CryptoData.Length));
        updates[5].CryptoData.CopyTo(expectedTranscript.AsMemory(clientHello.Length + updates[0].CryptoData.Length + updates[4].CryptoData.Length));

        byte[] actualTranscript = new byte[expectedTranscript.Length];
        Assert.True(schedule.TryCopyHandshakeTranscriptBytes(actualTranscript, out int bytesWritten));
        Assert.Equal(expectedTranscript.Length, bytesWritten);
        Assert.True(expectedTranscript.AsSpan().SequenceEqual(actualTranscript));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedServerRoleCertificateProgressionIsRejectedDeterministically()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);

        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Server);
        byte[] clientHello = CreateClientHelloTranscript(peerTransportParameters);

        progress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);

        QuicTlsKeySchedule schedule = new(QuicTlsRole.Server, localHandshakePrivateKey);
        Assert.Equal(6, schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters,
            localLeafCertificateDer).Count);

        IReadOnlyList<QuicTlsStateUpdate> repeatedUpdates = schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters,
            localLeafCertificateDer);

        Assert.Single(repeatedUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, repeatedUpdates[0].Kind);
        Assert.Equal((ushort)0x0032, repeatedUpdates[0].AlertDescription);
        Assert.Empty(schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters,
            localLeafCertificateDer));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleCommitRemainsUnavailableAfterLocalCertificate()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer);

        _ = driver.StartHandshake(localTransportParameters);
        _ = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));
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

    private static byte[] CreateClientHelloTranscript(QuicTransportParameters transportParameters)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Client,
            encodedTransportParameters,
            out int transportParametersBytesWritten));

        byte[] keyShare = CreateClientKeyShare();
        byte[] cipherSuites =
        [
            0x00,
            0x02,
            0x13,
            0x01,
        ];
        byte[] compressionMethods =
        [
            0x01,
            0x00,
        ];
        byte[] supportedVersionsExtension =
        [
            0x00, 0x2b,
            0x00, 0x03,
            0x02,
            0x03, 0x04,
        ];
        byte[] keyShareExtension = BuildClientKeyShareExtension(keyShare);
        byte[] transportParametersExtension = BuildTransportParametersExtension(
            encodedTransportParameters.AsSpan(0, transportParametersBytesWritten).ToArray());
        int extensionsLength = supportedVersionsExtension.Length + keyShareExtension.Length + transportParametersExtension.Length;
        byte[] body = new byte[2 + 32 + 1 + cipherSuites.Length + compressionMethods.Length + 2 + extensionsLength];
        int index = 0;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, 2), 0x0303);
        index += 2;
        CreateSequentialBytes(0x40, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;
        body[index++] = 0x00;
        cipherSuites.CopyTo(body.AsSpan(index, cipherSuites.Length));
        index += cipherSuites.Length;
        compressionMethods.CopyTo(body.AsSpan(index, compressionMethods.Length));
        index += compressionMethods.Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;
        supportedVersionsExtension.CopyTo(body.AsSpan(index, supportedVersionsExtension.Length));
        index += supportedVersionsExtension.Length;
        keyShareExtension.CopyTo(body.AsSpan(index, keyShareExtension.Length));
        index += keyShareExtension.Length;
        transportParametersExtension.CopyTo(body.AsSpan(index, transportParametersExtension.Length));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] BuildClientKeyShareExtension(byte[] keyShare)
    {
        byte[] extension = new byte[2 + 2 + 2 + 2 + 2 + keyShare.Length];
        int index = 0;
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(index, 2), 0x0033);
        index += 2;
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(index, 2), (ushort)(2 + 2 + 2 + keyShare.Length));
        index += 2;
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(index, 2), (ushort)(2 + 2 + keyShare.Length));
        index += 2;
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(index, 2), (ushort)QuicTlsNamedGroup.Secp256r1);
        index += 2;
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(index, 2), (ushort)keyShare.Length);
        index += 2;
        keyShare.CopyTo(extension.AsSpan(index, keyShare.Length));
        return extension;
    }

    private static byte[] BuildTransportParametersExtension(byte[] transportParameters)
    {
        byte[] extension = new byte[2 + 2 + transportParameters.Length];
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(2, 2), (ushort)transportParameters.Length);
        transportParameters.CopyTo(extension.AsSpan(4, transportParameters.Length));
        return extension;
    }

    private static byte[] CreateClientKeyShare()
    {
        using ECDiffieHellman clientKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        clientKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(0x33),
        });

        ECParameters parameters = clientKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[65];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    private static byte[] CreateRsaLeafCertificateDer()
    {
        using RSA leafKey = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=Incursa.Quic Server Certificate Continuation Test",
            leafKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        return certificate.Export(X509ContentType.Cert);
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, byte[] body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        transcript[1] = (byte)(body.Length >> 16);
        transcript[2] = (byte)(body.Length >> 8);
        transcript[3] = (byte)body.Length;
        body.CopyTo(transcript.AsSpan(4));
        return transcript;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }

    private static QuicTlsHandshakeMessageType ParseHandshakeMessageType(ReadOnlySpan<byte> handshakeMessageBytes)
    {
        return (QuicTlsHandshakeMessageType)handshakeMessageBytes[0];
    }
}

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0115")]
public sealed class REQ_QUIC_CRT_0115
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleEmitsLocalCertificateVerifyAfterLocalCertificateAtTheNextHandshakeOffset()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);
        byte[] expectedCertificateTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(localLeafCertificateDer);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.Equal(8, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[5].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[6].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[7].Kind);
        Assert.Equal(0UL, updates[1].CryptoDataOffset);
        Assert.Equal((ulong)updates[1].CryptoData.Length, updates[5].CryptoDataOffset);
        Assert.Equal((ulong)updates[1].CryptoData.Length + (ulong)updates[5].CryptoData.Length, updates[6].CryptoDataOffset);
        Assert.Equal(
            (ulong)updates[1].CryptoData.Length + (ulong)updates[5].CryptoData.Length + (ulong)updates[6].CryptoData.Length,
            updates[7].CryptoDataOffset);
        Assert.True(expectedCertificateTranscript.AsSpan().SequenceEqual(updates[6].CryptoData.Span));

        byte[] expectedTranscriptBeforeCertificateVerify =
        [
            .. CreateClientHelloTranscript(peerTransportParameters),
            .. updates[1].CryptoData.ToArray(),
            .. updates[5].CryptoData.ToArray(),
            .. updates[6].CryptoData.ToArray(),
        ];

        byte[] expectedCertificateVerifyTranscriptHash = SHA256.HashData(expectedTranscriptBeforeCertificateVerify);
        Assert.Equal(QuicTlsHandshakeMessageType.CertificateVerify, ParseHandshakeMessageType(updates[7].CryptoData.Span));
        Assert.True(TryParseCertificateVerifyTranscript(
            updates[7].CryptoData.Span,
            out QuicTlsSignatureScheme signatureScheme,
            out byte[] signature));
        Assert.Equal(QuicTlsSignatureScheme.EcdsaSecp256r1Sha256, signatureScheme);
        Assert.True(localCertificateKey.VerifyData(
            BuildCertificateVerifySignedData(expectedCertificateVerifyTranscriptHash),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));

        Span<byte> surfacedHandshakeBytes = stackalloc byte[
            updates[1].CryptoData.Length
            + updates[5].CryptoData.Length
            + updates[6].CryptoData.Length
            + updates[7].CryptoData.Length];
        Assert.True(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            surfacedHandshakeBytes,
            out ulong offset,
            out int bytesWritten));
        Assert.Equal(0UL, offset);
        Assert.Equal(surfacedHandshakeBytes.Length, bytesWritten);

        byte[] expectedHandshakeBytes =
        [
            .. updates[1].CryptoData.ToArray(),
            .. updates[5].CryptoData.ToArray(),
            .. updates[6].CryptoData.ToArray(),
            .. updates[7].CryptoData.ToArray(),
        ];
        Assert.True(expectedHandshakeBytes.AsSpan().SequenceEqual(surfacedHandshakeBytes));

        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.True(driver.State.TryGetHandshakeOpenPacketProtectionMaterial(out _));
        Assert.True(driver.State.TryGetHandshakeProtectPacketProtectionMaterial(out _));
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDoesNotEmitLocalCertificateVerifyWhenLocalSigningMaterialIsUnavailable()
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

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.Equal(7, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[^1].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Certificate, ParseHandshakeMessageType(updates[^1].CryptoData.Span));
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedLocalSigningMaterialFailsDeterministically()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] malformedLocalSigningPrivateKey = CreateScalar(0x44)[..^1];
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: malformedLocalSigningPrivateKey);

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(CreateClientTransportParameters()));

        Assert.Equal(2, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[1].Kind);
        Assert.Equal((ushort)0x0032, updates[1].AlertDescription);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.HandshakeKeysAvailable);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IncompatibleLocalCertificateAndSigningMaterialFailsDeterministically()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localCertificateScalar = CreateScalar(0x44);
        byte[] incompatibleLocalSigningPrivateKey = CreateScalar(0x45);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localCertificateScalar,
        });

        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: incompatibleLocalSigningPrivateKey);

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(CreateClientTransportParameters()));

        Assert.Equal(2, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[1].Kind);
        Assert.Equal((ushort)0x0033, updates[1].AlertDescription);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.HandshakeKeysAvailable);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleAppendsLocalCertificateVerifyToTheManagedTranscriptExplicitly()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);
        byte[] expectedCertificateTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(localLeafCertificateDer);

        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Server);
        byte[] clientHello = CreateClientHelloTranscript(peerTransportParameters);

        progress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);

        QuicTlsKeySchedule schedule = new(QuicTlsRole.Server, localHandshakePrivateKey);
        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters,
            localLeafCertificateDer,
            localSigningPrivateKey);

        Assert.Equal(7, updates.Count);
        byte[] expectedTranscript = new byte[
            clientHello.Length
            + updates[0].CryptoData.Length
            + updates[4].CryptoData.Length
            + updates[5].CryptoData.Length
            + updates[6].CryptoData.Length];
        clientHello.CopyTo(expectedTranscript, 0);
        updates[0].CryptoData.CopyTo(expectedTranscript.AsMemory(clientHello.Length));
        updates[4].CryptoData.CopyTo(expectedTranscript.AsMemory(clientHello.Length + updates[0].CryptoData.Length));
        updates[5].CryptoData.CopyTo(expectedTranscript.AsMemory(
            clientHello.Length + updates[0].CryptoData.Length + updates[4].CryptoData.Length));
        updates[6].CryptoData.CopyTo(expectedTranscript.AsMemory(
            clientHello.Length
            + updates[0].CryptoData.Length
            + updates[4].CryptoData.Length
            + updates[5].CryptoData.Length));

        byte[] actualTranscript = new byte[expectedTranscript.Length];
        Assert.True(schedule.TryCopyHandshakeTranscriptBytes(actualTranscript, out int bytesWritten));
        Assert.Equal(expectedTranscript.Length, bytesWritten);
        Assert.True(expectedTranscript.AsSpan().SequenceEqual(actualTranscript));
        Assert.True(expectedCertificateTranscript.AsSpan().SequenceEqual(updates[5].CryptoData.Span));
        Assert.Equal(QuicTlsHandshakeMessageType.CertificateVerify, ParseHandshakeMessageType(updates[6].CryptoData.Span));
        Assert.True(TryParseCertificateVerifyTranscript(
            updates[6].CryptoData.Span,
            out QuicTlsSignatureScheme signatureScheme,
            out byte[] signature));
        Assert.Equal(QuicTlsSignatureScheme.EcdsaSecp256r1Sha256, signatureScheme);

        byte[] expectedCertificateVerifyTranscriptHash = SHA256.HashData([
            .. clientHello,
            .. updates[0].CryptoData.ToArray(),
            .. updates[4].CryptoData.ToArray(),
            .. updates[5].CryptoData.ToArray(),
        ]);
        Assert.True(localCertificateKey.VerifyData(
            BuildCertificateVerifySignedData(expectedCertificateVerifyTranscriptHash),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedServerRoleCertificateVerifyProgressionIsRejectedDeterministically()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);

        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Server);
        byte[] clientHello = CreateClientHelloTranscript(peerTransportParameters);

        progress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);

        QuicTlsKeySchedule schedule = new(QuicTlsRole.Server, localHandshakePrivateKey);
        Assert.Equal(7, schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters,
            localLeafCertificateDer,
            localSigningPrivateKey).Count);

        IReadOnlyList<QuicTlsStateUpdate> repeatedUpdates = schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters,
            localLeafCertificateDer,
            localSigningPrivateKey);

        Assert.Single(repeatedUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, repeatedUpdates[0].Kind);
        Assert.Equal((ushort)0x0032, repeatedUpdates[0].AlertDescription);
        Assert.Empty(schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters,
            localLeafCertificateDer,
            localSigningPrivateKey));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleCommitRemainsUnavailableAfterLocalCertificateVerify()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        QuicTransportParameters localTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

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

    private static bool TryParseCertificateVerifyTranscript(
        ReadOnlySpan<byte> certificateVerifyTranscript,
        out QuicTlsSignatureScheme signatureScheme,
        out byte[] signature)
    {
        signatureScheme = default;
        signature = Array.Empty<byte>();

        if (certificateVerifyTranscript.Length <= 8
            || ParseHandshakeMessageType(certificateVerifyTranscript) != QuicTlsHandshakeMessageType.CertificateVerify)
        {
            return false;
        }

        ReadOnlySpan<byte> body = certificateVerifyTranscript[4..];
        signatureScheme = (QuicTlsSignatureScheme)BinaryPrimitives.ReadUInt16BigEndian(body);
        ushort signatureLength = BinaryPrimitives.ReadUInt16BigEndian(body[2..]);
        if (signatureScheme != QuicTlsSignatureScheme.EcdsaSecp256r1Sha256
            || signatureLength == 0
            || body.Length != 4 + signatureLength)
        {
            return false;
        }

        signature = body.Slice(4, signatureLength).ToArray();
        return true;
    }

    private static byte[] BuildCertificateVerifySignedData(ReadOnlySpan<byte> transcriptHash)
    {
        byte[] signedData = new byte[64 + ServerCertificateVerifyContext.Length + 1 + transcriptHash.Length];
        signedData.AsSpan(0, 64).Fill(0x20);
        Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify").CopyTo(signedData.AsSpan(64));
        signedData[64 + ServerCertificateVerifyContext.Length] = 0x00;
        transcriptHash.CopyTo(signedData.AsSpan(64 + ServerCertificateVerifyContext.Length + 1));
        return signedData;
    }

    private static readonly byte[] ServerCertificateVerifyContext =
        Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify");
}

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0116")]
public sealed class REQ_QUIC_CRT_0116
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleAppendsLocalFinishedToTheManagedTranscriptExplicitly()
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
        byte[] clientHello = CreateClientHelloTranscript(peerTransportParameters, out byte[] clientKeyShare);

        progress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);

        QuicTlsKeySchedule schedule = new(QuicTlsRole.Server, localHandshakePrivateKey);
        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters,
            localLeafCertificateDer,
            localSigningPrivateKey);

        Assert.Equal(8, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[4].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[5].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[6].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[7].Kind);
        Assert.Equal(0UL, updates[0].CryptoDataOffset);
        Assert.Equal(0UL, updates[4].CryptoDataOffset);
        Assert.Equal((ulong)updates[4].CryptoData.Length, updates[5].CryptoDataOffset);
        Assert.Equal(
            (ulong)updates[4].CryptoData.Length + (ulong)updates[5].CryptoData.Length,
            updates[6].CryptoDataOffset);
        Assert.Equal(
            (ulong)updates[4].CryptoData.Length
            + (ulong)updates[5].CryptoData.Length
            + (ulong)updates[6].CryptoData.Length,
            updates[7].CryptoDataOffset);

        byte[] expectedTranscript = new byte[
            clientHello.Length
            + updates[0].CryptoData.Length
            + updates[4].CryptoData.Length
            + updates[5].CryptoData.Length
            + updates[6].CryptoData.Length
            + updates[7].CryptoData.Length];
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
        updates[7].CryptoData.CopyTo(expectedTranscript.AsMemory(
            clientHello.Length
            + updates[0].CryptoData.Length
            + updates[4].CryptoData.Length
            + updates[5].CryptoData.Length
            + updates[6].CryptoData.Length));

        byte[] actualTranscript = new byte[expectedTranscript.Length];
        Assert.True(schedule.TryCopyHandshakeTranscriptBytes(actualTranscript, out int bytesWritten));
        Assert.Equal(expectedTranscript.Length, bytesWritten);
        Assert.True(expectedTranscript.AsSpan().SequenceEqual(actualTranscript));

        byte[] expectedServerHelloTranscriptHash = SHA256.HashData([
            .. clientHello,
            .. updates[0].CryptoData.ToArray(),
        ]);

        byte[] expectedFinishedVerifyData = CreateFinishedVerifyData(
            localHandshakePrivateKey,
            clientKeyShare,
            expectedServerHelloTranscriptHash,
            SHA256.HashData([
                .. clientHello,
                .. updates[0].CryptoData.ToArray(),
                .. updates[4].CryptoData.ToArray(),
                .. updates[5].CryptoData.ToArray(),
                .. updates[6].CryptoData.ToArray(),
            ]));

        Assert.Equal(QuicTlsHandshakeMessageType.Finished, ParseHandshakeMessageType(updates[7].CryptoData.Span));
        Assert.True(TryParseFinishedTranscript(updates[7].CryptoData.Span, out byte[] finishedVerifyData));
        Assert.True(expectedFinishedVerifyData.AsSpan().SequenceEqual(finishedVerifyData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDoesNotEmitLocalFinishedBeforeLocalCertificateVerifyExists()
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
            CreateClientHelloTranscript(peerTransportParameters, out _));

        Assert.Equal(7, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[^1].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Certificate, ParseHandshakeMessageType(updates[^1].CryptoData.Span));

        Span<byte> surfacedHandshakeBytes = stackalloc byte[
            updates[5].CryptoData.Length
            + updates[6].CryptoData.Length];
        Assert.True(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            surfacedHandshakeBytes,
            out ulong offset,
            out int bytesWritten));
        Assert.Equal(0UL, offset);
        Assert.Equal(surfacedHandshakeBytes.Length, bytesWritten);

        byte[] expectedHandshakeBytes =
        [
            .. updates[5].CryptoData.ToArray(),
            .. updates[6].CryptoData.ToArray(),
        ];
        Assert.True(expectedHandshakeBytes.AsSpan().SequenceEqual(surfacedHandshakeBytes));
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedServerRoleFinishedProgressionIsRejectedDeterministically()
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
        byte[] clientHello = CreateClientHelloTranscript(peerTransportParameters, out _);

        progress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);

        QuicTlsKeySchedule schedule = new(QuicTlsRole.Server, localHandshakePrivateKey);
        Assert.Equal(8, schedule.ProcessTranscriptStep(
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
    public void ServerRoleCommitRemainsUnavailableAfterLocalFinished()
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
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters, out _));

        Assert.Equal(9, updates.Count);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, ParseHandshakeMessageType(updates[^1].CryptoData.Span));
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

    private static byte[] CreateClientHelloTranscript(QuicTransportParameters transportParameters, out byte[] keyShare)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Client,
            encodedTransportParameters,
            out int transportParametersBytesWritten));

        keyShare = CreateClientKeyShare();
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

    private static byte[] CreateFinishedVerifyData(
        ReadOnlySpan<byte> localHandshakePrivateKey,
        ReadOnlySpan<byte> clientKeyShare,
        ReadOnlySpan<byte> serverHelloTranscriptHash,
        ReadOnlySpan<byte> finishedTranscriptHash)
    {
        byte[] serverHandshakeTrafficSecret = DeriveServerHandshakeTrafficSecret(
            localHandshakePrivateKey,
            clientKeyShare,
            serverHelloTranscriptHash);
        byte[] finishedKey = HkdfExpandLabel(serverHandshakeTrafficSecret, FinishedLabel, [], HashLength);
        using HMACSHA256 hmac = new(finishedKey);
        return hmac.ComputeHash(finishedTranscriptHash.ToArray());
    }

    private static byte[] DeriveServerHandshakeTrafficSecret(
        ReadOnlySpan<byte> localHandshakePrivateKey,
        ReadOnlySpan<byte> clientKeyShare,
        ReadOnlySpan<byte> serverHelloTranscriptHash)
    {
        using ECDiffieHellman localKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        localKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localHandshakePrivateKey.ToArray(),
        });

        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        peer.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = clientKeyShare.Slice(1, Secp256r1CoordinateLength).ToArray(),
                Y = clientKeyShare.Slice(1 + Secp256r1CoordinateLength, Secp256r1CoordinateLength).ToArray(),
            },
        });

        byte[] sharedSecret = localKeyPair.DeriveKeyMaterial(peer.PublicKey);
        byte[] earlySecret = HkdfExtract(new byte[HashLength], []);
        byte[] derivedSecret = HkdfExpandLabel(earlySecret, DerivedLabel, EmptyTranscriptHash, HashLength);
        byte[] handshakeSecret = HkdfExtract(derivedSecret, sharedSecret);
        return HkdfExpandLabel(handshakeSecret, ServerHandshakeTrafficLabel, serverHelloTranscriptHash, HashLength);
    }

    private static bool TryParseFinishedTranscript(ReadOnlySpan<byte> finishedTranscript, out byte[] verifyData)
    {
        verifyData = Array.Empty<byte>();

        if (finishedTranscript.Length <= 4
            || ParseHandshakeMessageType(finishedTranscript) != QuicTlsHandshakeMessageType.Finished)
        {
            return false;
        }

        ReadOnlySpan<byte> body = finishedTranscript[4..];
        if (body.Length != HashLength)
        {
            return false;
        }

        verifyData = body.ToArray();
        return true;
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
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

    private static byte[] HkdfExtract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial)
    {
        using HMACSHA256 hmac = new(salt.ToArray());
        return hmac.ComputeHash(inputKeyMaterial.ToArray());
    }

    private static byte[] HkdfExpandLabel(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int length)
    {
        const int HkdfLengthFieldLength = sizeof(ushort);
        const int HkdfLabelLengthFieldLength = 1;
        const int HkdfContextLengthFieldLength = 1;
        const int HkdfExpandCounterLength = 1;
        const byte HkdfExpandCounterValue = 1;
        byte[] hkdfLabelPrefix = Encoding.ASCII.GetBytes("tls13 ");

        int hkdfLabelLength = HkdfLengthFieldLength
            + HkdfLabelLengthFieldLength
            + hkdfLabelPrefix.Length
            + label.Length
            + HkdfContextLengthFieldLength
            + context.Length;

        Span<byte> hkdfLabel = stackalloc byte[hkdfLabelLength];
        int index = 0;

        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel, checked((ushort)length));
        index += HkdfLengthFieldLength;

        hkdfLabel[index++] = checked((byte)(hkdfLabelPrefix.Length + label.Length));
        hkdfLabelPrefix.CopyTo(hkdfLabel[index..]);
        index += hkdfLabelPrefix.Length;

        label.CopyTo(hkdfLabel[index..]);
        index += label.Length;

        hkdfLabel[index++] = checked((byte)context.Length);
        if (!context.IsEmpty)
        {
            context.CopyTo(hkdfLabel[index..]);
        }

        byte[] expandInput = new byte[hkdfLabel.Length + HkdfExpandCounterLength];
        hkdfLabel.CopyTo(expandInput);
        expandInput[^1] = HkdfExpandCounterValue;

        using HMACSHA256 hmac = new(secret.ToArray());
        byte[] output = hmac.ComputeHash(expandInput);
        if (output.Length == length)
        {
            return output;
        }

        byte[] truncated = new byte[length];
        output.AsSpan(..length).CopyTo(truncated);
        return truncated;
    }

    private static readonly byte[] EmptyTranscriptHash = SHA256.HashData(Array.Empty<byte>());
    private static readonly byte[] DerivedLabel = Encoding.ASCII.GetBytes("derived");
    private static readonly byte[] FinishedLabel = Encoding.ASCII.GetBytes("finished");
    private static readonly byte[] ServerHandshakeTrafficLabel = Encoding.ASCII.GetBytes("s hs traffic");
    private const int HashLength = 32;
    private const int Secp256r1CoordinateLength = 32;
    private const int UInt16Length = 2;
    private const int UInt24Length = 3;
}

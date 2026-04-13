using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0123")]
public sealed class REQ_QUIC_CRT_0123
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientCertificatePolicySnapshotIsImmutableAndTraversesTheManagedClientSettingsRuntimeAndBridge()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        byte[] exactPeerIdentitySource = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(
            ECDsa.Create(ECCurve.NamedCurves.nistP256));
        byte[] explicitTrustMaterialSource = SHA256.HashData(exactPeerIdentitySource);
        byte[] expectedIdentity = exactPeerIdentitySource.ToArray();
        byte[] expectedTrust = explicitTrustMaterialSource.ToArray();

        IPEndPoint remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionOptions options = new()
        {
            RemoteEndPoint = remoteEndPoint,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            },
        };
        options.PeerCertificatePolicy = new QuicPeerCertificatePolicy
        {
            ExactPeerLeafCertificateDer = exactPeerIdentitySource,
            ExplicitTrustMaterialSha256 = explicitTrustMaterialSource,
        };

        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            options,
            nameof(options));

        exactPeerIdentitySource[0] ^= 0x80;
        explicitTrustMaterialSource[0] ^= 0x80;

        Assert.NotNull(settings.Options.PeerCertificatePolicy);
        Assert.NotSame(options.PeerCertificatePolicy, settings.Options.PeerCertificatePolicy);
        Assert.Equal(expectedIdentity, settings.Options.PeerCertificatePolicy!.ExactPeerLeafCertificateDer.ToArray());
        Assert.Equal(expectedTrust, settings.Options.PeerCertificatePolicy.ExplicitTrustMaterialSha256.ToArray());
        Assert.NotNull(settings.ClientCertificatePolicySnapshot);
        Assert.Equal(expectedIdentity, settings.ClientCertificatePolicySnapshot!.ExactPeerLeafCertificateDer.ToArray());
        Assert.Equal(expectedTrust, settings.ClientCertificatePolicySnapshot.ExplicitTrustMaterialSha256.ToArray());

        await using QuicClientConnectionHost host = new(settings);

        QuicClientConnectionSettings capturedSettings = GetPrivateField<QuicClientConnectionSettings>(host, "settings");
        Assert.NotNull(capturedSettings.Options.PeerCertificatePolicy);
        Assert.Equal(expectedIdentity, capturedSettings.Options.PeerCertificatePolicy!.ExactPeerLeafCertificateDer.ToArray());
        Assert.Equal(expectedTrust, capturedSettings.Options.PeerCertificatePolicy.ExplicitTrustMaterialSha256.ToArray());
        Assert.Equal(expectedIdentity, capturedSettings.ClientCertificatePolicySnapshot!.ExactPeerLeafCertificateDer.ToArray());
        Assert.Equal(expectedTrust, capturedSettings.ClientCertificatePolicySnapshot.ExplicitTrustMaterialSha256.ToArray());

        QuicConnection connection = GetPrivateField<QuicConnection>(host, "connection");
        QuicConnectionRuntime runtime = GetPrivateField<QuicConnectionRuntime>(connection, "runtime");
        Assert.Equal(expectedIdentity, runtime.ClientCertificatePolicySnapshot!.ExactPeerLeafCertificateDer.ToArray());
        Assert.Equal(expectedTrust, runtime.ClientCertificatePolicySnapshot.ExplicitTrustMaterialSha256.ToArray());

        QuicTlsTransportBridgeDriver driver = GetPrivateField<QuicTlsTransportBridgeDriver>(runtime, "tlsBridgeDriver");
        QuicClientCertificatePolicySnapshot driverSnapshot = GetPrivateField<QuicClientCertificatePolicySnapshot>(driver, "clientCertificatePolicySnapshot");
        Assert.Equal(expectedIdentity, driverSnapshot.ExactPeerLeafCertificateDer.ToArray());
        Assert.Equal(expectedTrust, driverSnapshot.ExplicitTrustMaterialSha256.ToArray());

        _ = localHandshakePrivateKey;
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleDriverPublishesPolicyAcceptanceOnlyWhenSnapshotValuesMatchThePresentedLeafCertificate()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] explicitTrustMaterial = SHA256.HashData(leafCertificateDer);
        QuicClientCertificatePolicySnapshot snapshot = new(leafCertificateDer, explicitTrustMaterial);
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            clientCertificatePolicySnapshot: snapshot);

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(localTransportParameters);
        Assert.Equal(2, bootstrapUpdates.Count);

        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            byte[] certificateTranscript,
            byte[] certificateVerifyTranscript,
            byte[] finishedTranscript) = CreateClientHandshakeTranscriptParts(
            bootstrapUpdates[1].CryptoData,
            localHandshakePrivateKey,
            peerTransportParameters,
            leafKey,
            leafCertificateDer);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            serverHelloTranscript);
        Assert.Equal(4, serverHelloUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, serverHelloUpdates[3].Kind);

        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            encryptedExtensionsTranscript));

        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateTranscript));

        IReadOnlyList<QuicTlsStateUpdate> certificateVerifyUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateVerifyTranscript);

        Assert.Equal(3, certificateVerifyUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.PeerCertificateVerifyVerified, certificateVerifyUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerCertificatePolicyAccepted, certificateVerifyUpdates[2].Kind);
        Assert.True(driver.State.PeerCertificatePolicyAccepted);

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);

        Assert.Equal(7, finishedUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable, finishedUpdates[4].Kind);
        Assert.Equal(QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable, finishedUpdates[5].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted, finishedUpdates[6].Kind);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverRejectsMismatchedExplicitTrustMaterialDeterministically()
    {
        AssertSnapshotMismatchFailsClosed(
            snapshotFactory: leafCertificateDer => new QuicClientCertificatePolicySnapshot(
                leafCertificateDer,
                MutateFirstByte(SHA256.HashData(leafCertificateDer))),
            expectedAlertDescription: 0x0031);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverRejectsMismatchedExactPeerIdentityDeterministically()
    {
        AssertSnapshotMismatchFailsClosed(
            snapshotFactory: leafCertificateDer => new QuicClientCertificatePolicySnapshot(
                MutateFirstByte(leafCertificateDer),
                SHA256.HashData(leafCertificateDer)),
            expectedAlertDescription: 0x0031);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverRejectsMissingExplicitTrustMaterialDeterministically()
    {
        AssertSnapshotMismatchFailsClosed(
            snapshotFactory: leafCertificateDer => new QuicClientCertificatePolicySnapshot(
                leafCertificateDer,
                ReadOnlyMemory<byte>.Empty),
            expectedAlertDescription: 0x0031);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverRejectsMissingExactPeerIdentityDeterministically()
    {
        AssertSnapshotMismatchFailsClosed(
            snapshotFactory: leafCertificateDer => new QuicClientCertificatePolicySnapshot(
                ReadOnlyMemory<byte>.Empty,
                SHA256.HashData(leafCertificateDer)),
            expectedAlertDescription: 0x0031);
    }

    private static void AssertSnapshotMismatchFailsClosed(
        Func<byte[], QuicClientCertificatePolicySnapshot> snapshotFactory,
        ushort expectedAlertDescription)
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            clientCertificatePolicySnapshot: snapshotFactory(leafCertificateDer));

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(localTransportParameters);
        Assert.Equal(2, bootstrapUpdates.Count);

        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            byte[] certificateTranscript,
            byte[] certificateVerifyTranscript,
            byte[] finishedTranscript) = CreateClientHandshakeTranscriptParts(
            bootstrapUpdates[1].CryptoData,
            localHandshakePrivateKey,
            peerTransportParameters,
            leafKey,
            leafCertificateDer);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            serverHelloTranscript);
        Assert.Equal(4, serverHelloUpdates.Count);

        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            encryptedExtensionsTranscript));

        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateTranscript));

        IReadOnlyList<QuicTlsStateUpdate> certificateVerifyUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateVerifyTranscript);

        Assert.Equal(3, certificateVerifyUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.PeerCertificateVerifyVerified, certificateVerifyUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, certificateVerifyUpdates[2].Kind);
        Assert.Equal(expectedAlertDescription, certificateVerifyUpdates[2].AlertDescription);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.PeerCertificatePolicyAccepted);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.Empty(driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, finishedTranscript));
    }

    private static (
        byte[] ServerHelloTranscript,
        byte[] EncryptedExtensionsTranscript,
        byte[] CertificateTranscript,
        byte[] CertificateVerifyTranscript,
        byte[] FinishedTranscript) CreateClientHandshakeTranscriptParts(
        ReadOnlyMemory<byte> clientHelloTranscript,
        ReadOnlyMemory<byte> localHandshakePrivateKey,
        QuicTransportParameters peerTransportParameters,
        ECDsa leafKey,
        byte[] leafCertificateDer)
    {
        QuicTlsKeySchedule schedule = new(localHandshakePrivateKey);
        schedule.AppendLocalHandshakeMessage(clientHelloTranscript.Span);

        byte[] serverHello = CreateServerHelloTranscript();
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(peerTransportParameters);
        byte[] certificate = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(leafCertificateDer);
        byte[] certificateVerifyTranscriptHash = SHA256.HashData([
            .. clientHelloTranscript.Span,
            .. serverHello,
            .. encryptedExtensions,
            .. certificate,
        ]);
        byte[] certificateVerify = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            certificateVerifyTranscriptHash);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = schedule.ProcessTranscriptStep(CreateServerHelloStep(serverHello));
        Assert.Equal(3, serverHelloUpdates.Count);
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] serverHelloOnlyVerifyData));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(leafCertificateDer)));
        Assert.Single(schedule.ProcessTranscriptStep(CreateCertificateVerifyStep(certificateVerify)));
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] finishedVerifyData));
        Assert.False(serverHelloOnlyVerifyData.SequenceEqual(finishedVerifyData));

        return (
            serverHello,
            encryptedExtensions,
            certificate,
            certificateVerify,
            CreateFinishedTranscript(finishedVerifyData));
    }

    private static QuicTlsTranscriptStep CreateServerHelloStep(byte[] transcriptBytes)
    {
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            NamedGroup: QuicTlsNamedGroup.Secp256r1,
            KeyShare: CreateServerKeyShare(),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateEncryptedExtensionsStep(QuicTransportParameters transportParameters)
    {
        byte[] transcriptBytes = CreateEncryptedExtensionsTranscript(transportParameters);
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.PeerTransportParametersStaged,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            TransportParameters: transportParameters,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateCertificateStep(byte[] leafCertificateDer)
    {
        byte[] transcriptBytes = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(leafCertificateDer);
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Certificate,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateCertificateVerifyStep(byte[] certificateVerifyTranscript)
    {
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: (uint)(certificateVerifyTranscript.Length - 4),
            HandshakeMessageBytes: certificateVerifyTranscript);
    }

    private static byte[] CreateFinishedTranscript(ReadOnlySpan<byte> finishedVerifyData)
    {
        byte[] transcriptBytes = new byte[4 + finishedVerifyData.Length];
        transcriptBytes[0] = (byte)QuicTlsHandshakeMessageType.Finished;
        WriteUInt24(transcriptBytes.AsSpan(1, 3), finishedVerifyData.Length);
        finishedVerifyData.CopyTo(transcriptBytes.AsSpan(4));
        return transcriptBytes;
    }

    private static byte[] CreateServerHelloTranscript()
    {
        byte[] keyShare = CreateServerKeyShare();
        int extensionsLength = 6 + 4 + 2 + 2 + keyShare.Length;
        byte[] body = new byte[40 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;

        CreateSequentialBytes(0x40, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;

        body[index++] = 0;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256);
        index += 2;
        body[index++] = 0x00;

        WriteUInt16(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;

        WriteUInt16(body.AsSpan(index, 2), 0x002b);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), 2);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), 0x0304);
        index += 2;

        WriteUInt16(body.AsSpan(index, 2), 0x0033);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)(2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsNamedGroup.Secp256r1);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)keyShare.Length);
        index += 2;
        keyShare.CopyTo(body.AsSpan(index, keyShare.Length));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
    }

    private static byte[] CreateEncryptedExtensionsTranscript(QuicTransportParameters transportParameters)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Server,
            encodedTransportParameters,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));

        byte[] transcript = new byte[512];
        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicEncryptedExtensionsTransportParametersMessage(
            parsedTransportParameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int messageBytesWritten));

        Array.Resize(ref transcript, messageBytesWritten);
        return transcript;
    }

    private static byte[] CreateServerKeyShare()
    {
        using ECDiffieHellman serverKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        serverKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(0x02),
        });

        ECParameters parameters = serverKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[1 + (2 * 32)];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, 3), body.Length);
        body.CopyTo(transcript.AsSpan(4));
        return transcript;
    }

    private static void WriteUInt16(Span<byte> destination, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, value);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static byte[] CreateSequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(seed + index));
        }

        return bytes;
    }

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 9443,
                IPv6Address = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
                IPv6Port = 9553,
                ConnectionId = [0x44, 0x55],
                StatelessResetToken = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F],
            },
            ActiveConnectionIdLimit = 4,
        };
    }

    private static byte[] MutateFirstByte(ReadOnlySpan<byte> source)
    {
        byte[] mutated = source.ToArray();
        mutated[0] ^= 0x80;
        return mutated;
    }

    private static T GetPrivateField<T>(object target, string fieldName)
    {
        FieldInfo? field = target.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic);
        if (field is null)
        {
            throw new InvalidOperationException($"Field '{fieldName}' was not found on {target.GetType().FullName}.");
        }

        object? value = field.GetValue(target);
        return value is null ? default! : (T)value;
    }
}

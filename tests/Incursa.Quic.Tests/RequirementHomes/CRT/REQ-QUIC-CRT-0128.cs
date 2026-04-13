using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0128")]
public sealed class REQ_QUIC_CRT_0128
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleDriverSurfacesOpaquePostHandshakeTicketBytesAfterFinished()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

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
        Assert.Equal(QuicTlsUpdateKind.PeerCertificatePolicyAccepted, certificateVerifyUpdates[2].Kind);

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);
        Assert.Equal(7, finishedUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted, finishedUpdates[6].Kind);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(driver.State.OneRttProtectPacketProtectionMaterial.HasValue);

        byte[] ticketBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.PublishPostHandshakeTicket(ticketBytes);

        Assert.Single(ticketUpdates);
        Assert.Equal(QuicTlsUpdateKind.PostHandshakeTicketAvailable, ticketUpdates[0].Kind);
        Assert.Equal(ticketBytes, ticketUpdates[0].TicketBytes.ToArray());
        Assert.Equal(ticketBytes, driver.State.PostHandshakeTicketBytes.ToArray());
        Assert.True(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(driver.State.OneRttProtectPacketProtectionMaterial.HasValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverRejectsPostHandshakeTicketsBeforeFinishedAndKeepsEarlyDataClosed()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.Equal(2, driver.StartHandshake(localTransportParameters).Count);
        Assert.Empty(driver.PublishPostHandshakeTicket(new byte[] { 0x01, 0x02, 0x03 }));
        Assert.Empty(driver.PublishPostHandshakeTicket(new byte[] { 0x04, 0x05, 0x06 }));

        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PostHandshakeTicketBytes.IsEmpty);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.OneRttKeysAvailable);
        Assert.Null(driver.State.OneRttOpenPacketProtectionMaterial);
        Assert.Null(driver.State.OneRttProtectPacketProtectionMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverRejectsDuplicatePostHandshakeTicketsAndKeepsTheFirstOpaquePayload()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(localTransportParameters);
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

        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, serverHelloTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, encryptedExtensionsTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, certificateTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, certificateVerifyTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, finishedTranscript);

        byte[] firstTicketBytes = [0x10, 0x20, 0x30];
        byte[] duplicateTicketBytes = [0x40, 0x50, 0x60];

        Assert.Single(driver.PublishPostHandshakeTicket(firstTicketBytes));
        Assert.Empty(driver.PublishPostHandshakeTicket(duplicateTicketBytes));
        Assert.Equal(firstTicketBytes, driver.State.PostHandshakeTicketBytes.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDriverRejectsPostHandshakeTicketPublication()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);

        Assert.Empty(driver.PublishPostHandshakeTicket(new byte[] { 0x01, 0x02, 0x03 }));
        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PostHandshakeTicketBytes.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverSafelyIgnoresUnsupportedOneRttPostHandshakeCryptoMessages()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(localTransportParameters);
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

        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, serverHelloTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, encryptedExtensionsTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, certificateTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, certificateVerifyTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, finishedTranscript);

        IReadOnlyList<QuicTlsStateUpdate> unsupportedPostHandshakeUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            new byte[] { 0x01, 0x02, 0x03 });

        Assert.Empty(unsupportedPostHandshakeUpdates);
        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(driver.State.OneRttProtectPacketProtectionMaterial.HasValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceDoesNotExposeResumptionTicketOrEarlyDataPromises()
    {
        string[] forbiddenFragments = ["Resum", "Ticket", "EarlyData"];

        string[] publicMembers = typeof(QuicConnection).Assembly
            .GetExportedTypes()
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(member => $"{type.FullName}.{member.Name}"))
            .Concat(
                typeof(QuicConnection).Assembly.GetExportedTypes()
                    .Select(type => type.FullName ?? type.Name))
            .ToArray();

        Assert.DoesNotContain(publicMembers, member =>
            forbiddenFragments.Any(fragment => member.Contains(fragment, StringComparison.OrdinalIgnoreCase)));
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
            MaxIdleTimeout = 21,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
        };
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

    private static byte[] CreateFinishedTranscript(ReadOnlySpan<byte> verifyData)
    {
        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Finished, verifyData);
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
        destination[0] = checked((byte)((value >> 16) & 0xFF));
        destination[1] = checked((byte)((value >> 8) & 0xFF));
        destination[2] = checked((byte)(value & 0xFF));
    }
}

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0107")]
public sealed class REQ_QUIC_CRT_0107
{
    private const ushort SupportedGroupsExtensionType = 0x000A;

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleConsumesAnOrderedHandshakeTranscriptAndStagesPeerTransportParametersFromEncryptedExtensions()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] serverHello = CreateServerHelloTranscript(QuicTlsCipherSuite.TlsAes128GcmSha256);
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(CreateServerTransportParameters());
        byte[] certificate = CreateCertificateTranscript();
        byte[] certificateVerify = CreateCertificateVerifyTranscript();
        byte[] finished = CreateFinishedTranscript(QuicTlsTranscriptHashAlgorithm.Sha256);

        progress.AppendCryptoBytes(0, serverHello[..5]);
        Assert.Equal(QuicTlsTranscriptStepKind.None, progress.Advance(QuicTlsRole.Client).Kind);
        Assert.Equal(5UL, progress.IngressCursor);
        Assert.True(progress.HasPendingBytes);
        Assert.Null(progress.StagedPeerTransportParameters);

        progress.AppendCryptoBytes(progress.IngressCursor, serverHello[5..]);
        QuicTlsTranscriptStep serverHelloStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, serverHelloStep.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, serverHelloStep.HandshakeMessageType);
        Assert.Equal((uint)(serverHello.Length - 4), serverHelloStep.HandshakeMessageLength);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, serverHelloStep.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, serverHelloStep.TranscriptHashAlgorithm);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, serverHelloStep.TranscriptPhase);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, progress.Phase);
        Assert.Null(progress.StagedPeerTransportParameters);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, progress.HandshakeMessageType);
        Assert.Equal((uint)(serverHello.Length - 4), progress.HandshakeMessageLength);

        progress.AppendCryptoBytes(progress.IngressCursor, encryptedExtensions);
        QuicTlsTranscriptStep encryptedExtensionsStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, encryptedExtensionsStep.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, encryptedExtensionsStep.HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, encryptedExtensionsStep.TranscriptPhase);
        Assert.NotNull(encryptedExtensionsStep.TransportParameters);
        Assert.Equal(30UL, encryptedExtensionsStep.TransportParameters!.MaxIdleTimeout);
        Assert.True(encryptedExtensionsStep.TransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, encryptedExtensionsStep.TransportParameters.InitialSourceConnectionId);
        Assert.NotNull(encryptedExtensionsStep.TransportParameters.PreferredAddress);
        Assert.Equal(new byte[] { 192, 0, 2, 1 }, encryptedExtensionsStep.TransportParameters.PreferredAddress!.IPv4Address);
        Assert.Equal(9443, encryptedExtensionsStep.TransportParameters.PreferredAddress.IPv4Port);
        Assert.Equal(new byte[] { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }, encryptedExtensionsStep.TransportParameters.PreferredAddress.IPv6Address);
        Assert.Equal(9553, encryptedExtensionsStep.TransportParameters.PreferredAddress.IPv6Port);
        Assert.Equal(new byte[] { 0x44, 0x55 }, encryptedExtensionsStep.TransportParameters.PreferredAddress.ConnectionId);
        Assert.Equal(new byte[] { 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F }, encryptedExtensionsStep.TransportParameters.PreferredAddress.StatelessResetToken);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, progress.Phase);
        Assert.NotNull(progress.StagedPeerTransportParameters);

        progress.AppendCryptoBytes(progress.IngressCursor, certificate);
        QuicTlsTranscriptStep certificateStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, certificateStep.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Certificate, certificateStep.HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, certificateStep.TranscriptPhase);
        Assert.Null(certificateStep.TransportParameters);
        Assert.Equal(QuicTlsHandshakeMessageType.Certificate, progress.HandshakeMessageType);
        Assert.Equal((uint)(certificate.Length - 4), progress.HandshakeMessageLength);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, progress.Phase);

        progress.AppendCryptoBytes(progress.IngressCursor, certificateVerify);
        QuicTlsTranscriptStep certificateVerifyStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, certificateVerifyStep.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.CertificateVerify, certificateVerifyStep.HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, certificateVerifyStep.TranscriptPhase);
        Assert.Null(certificateVerifyStep.TransportParameters);
        Assert.Equal(QuicTlsHandshakeMessageType.CertificateVerify, progress.HandshakeMessageType);
        Assert.Equal((uint)(certificateVerify.Length - 4), progress.HandshakeMessageLength);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, progress.Phase);

        progress.AppendCryptoBytes(progress.IngressCursor, finished);
        QuicTlsTranscriptStep finishedStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, finishedStep.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, finishedStep.HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, finishedStep.TranscriptPhase);
        Assert.Null(finishedStep.TransportParameters);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, progress.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, progress.TranscriptHashAlgorithm);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, progress.HandshakeMessageType);
        Assert.Equal((uint)(finished.Length - 4), progress.HandshakeMessageLength);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, progress.Phase);
        Assert.False(progress.IsTerminalFailure);
        Assert.Null(progress.TerminalAlertDescription);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleStagesPeerTransportParametersOnlyFromClientHello()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Server);
        byte[] clientHello = CreateClientHelloTranscript(CreateClientTransportParameters());

        progress.AppendCryptoBytes(0, clientHello[..7]);
        Assert.Equal(QuicTlsTranscriptStepKind.None, progress.Advance(QuicTlsRole.Server).Kind);
        Assert.Equal(7UL, progress.IngressCursor);
        Assert.True(progress.HasPendingBytes);
        Assert.Null(progress.StagedPeerTransportParameters);

        progress.AppendCryptoBytes(progress.IngressCursor, clientHello[7..]);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);

        Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, clientHelloStep.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, clientHelloStep.HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, clientHelloStep.TranscriptPhase);
        Assert.NotNull(clientHelloStep.TransportParameters);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, clientHelloStep.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, clientHelloStep.TranscriptHashAlgorithm);
        Assert.Equal(21UL, clientHelloStep.TransportParameters!.MaxIdleTimeout);
        Assert.True(clientHelloStep.TransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, clientHelloStep.TransportParameters.InitialSourceConnectionId);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, progress.Phase);
        Assert.NotNull(progress.StagedPeerTransportParameters);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, progress.HandshakeMessageType);
        Assert.Equal((uint)(clientHello.Length - 4), progress.HandshakeMessageLength);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, progress.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, progress.TranscriptHashAlgorithm);
        Assert.False(progress.IsTerminalFailure);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleAcceptsSupportedGroupsEncryptedExtensionsAlongsideTransportParameters()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] serverHello = CreateServerHelloTranscript(QuicTlsCipherSuite.TlsAes128GcmSha256);
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(
            CreateServerTransportParameters(),
            includeSupportedGroupsExtension: true);

        progress.AppendCryptoBytes(0, serverHello);
        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, progress.Advance(QuicTlsRole.Client).Kind);

        progress.AppendCryptoBytes(progress.IngressCursor, encryptedExtensions);
        QuicTlsTranscriptStep step = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, step.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, step.HandshakeMessageType);
        Assert.NotNull(step.TransportParameters);
        Assert.False(progress.IsTerminalFailure);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnexpectedHandshakeMessageOrderIsRejectedDeterministically()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(CreateServerTransportParameters());

        progress.AppendCryptoBytes(0, encryptedExtensions);
        QuicTlsTranscriptStep step = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, step.Kind);
        Assert.Equal((ushort)0x0032, step.AlertDescription);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, progress.Phase);
        Assert.True(progress.IsTerminalFailure);
        Assert.Equal((ushort)0x0032, progress.TerminalAlertDescription);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DuplicateHandshakeMessagesAreRejectedDeterministically()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] serverHello = CreateServerHelloTranscript(QuicTlsCipherSuite.TlsAes128GcmSha256);

        progress.AppendCryptoBytes(0, serverHello);
        QuicTlsTranscriptStep firstStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, firstStep.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, firstStep.HandshakeMessageType);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, firstStep.SelectedCipherSuite);

        progress.AppendCryptoBytes(progress.IngressCursor, serverHello);
        QuicTlsTranscriptStep repeatedStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, repeatedStep.Kind);
        Assert.Equal((ushort)0x0032, repeatedStep.AlertDescription);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, progress.Phase);
        Assert.True(progress.IsTerminalFailure);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransportParameterExtensionPlacementIsRejectedWhenItIsIllegalOrRepeated()
    {
        QuicTlsTranscriptProgress illegalPlacementProgress = new(QuicTlsRole.Client);
        byte[] serverHelloWithTransportParameters = CreateServerHelloTranscript(
            QuicTlsCipherSuite.TlsAes128GcmSha256,
            includeTransportParametersExtension: true);

        illegalPlacementProgress.AppendCryptoBytes(0, serverHelloWithTransportParameters);
        QuicTlsTranscriptStep illegalPlacementStep = illegalPlacementProgress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, illegalPlacementStep.Kind);
        Assert.Equal((ushort)0x0032, illegalPlacementStep.AlertDescription);

        QuicTlsTranscriptProgress repeatedPlacementProgress = new(QuicTlsRole.Client);
        byte[] repeatedTransportParameters = CreateEncryptedExtensionsTranscript(
            CreateServerTransportParameters(),
            duplicateTransportParametersExtension: true);

        repeatedPlacementProgress.AppendCryptoBytes(0, repeatedTransportParameters);
        QuicTlsTranscriptStep repeatedPlacementStep = repeatedPlacementProgress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, repeatedPlacementStep.Kind);
        Assert.Equal((ushort)0x0032, repeatedPlacementStep.AlertDescription);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, repeatedPlacementProgress.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnexpectedEncryptedExtensionsPeerExtensionsAreRejectedDeterministically()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(
            CreateServerTransportParameters(),
            includeUnknownExtension: true);

        progress.AppendCryptoBytes(0, encryptedExtensions);
        QuicTlsTranscriptStep step = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, step.Kind);
        Assert.Equal((ushort)0x0032, step.AlertDescription);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, progress.Phase);
        Assert.True(progress.IsTerminalFailure);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedSupportedGroupsEncryptedExtensionsAreRejectedDeterministically()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] serverHello = CreateServerHelloTranscript(QuicTlsCipherSuite.TlsAes128GcmSha256);
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(
            CreateServerTransportParameters(),
            includeMalformedSupportedGroupsExtension: true);

        progress.AppendCryptoBytes(0, serverHello);
        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, progress.Advance(QuicTlsRole.Client).Kind);

        progress.AppendCryptoBytes(progress.IngressCursor, encryptedExtensions);
        QuicTlsTranscriptStep step = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, step.Kind);
        Assert.Equal((ushort)0x0032, step.AlertDescription);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, progress.Phase);
        Assert.True(progress.IsTerminalFailure);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TruncatedOrMalformedHandshakeFramingFailsDeterministically()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] malformedEncryptedExtensions = CreateMalformedEncryptedExtensionsTranscript();

        progress.AppendCryptoBytes(0, malformedEncryptedExtensions);
        QuicTlsTranscriptStep step = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, step.Kind);
        Assert.Equal((ushort)0x0032, step.AlertDescription);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, progress.Phase);
        Assert.True(progress.IsTerminalFailure);
        Assert.Equal((ushort)0x0032, progress.TerminalAlertDescription);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FatalTranscriptStateBlocksFurtherProgression()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] malformedEncryptedExtensions = CreateMalformedEncryptedExtensionsTranscript();
        byte[] validServerHello = CreateServerHelloTranscript(QuicTlsCipherSuite.TlsAes128GcmSha256);

        progress.AppendCryptoBytes(0, malformedEncryptedExtensions);
        QuicTlsTranscriptStep fatalStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, fatalStep.Kind);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, progress.Phase);
        Assert.True(progress.IsTerminalFailure);

        progress.AppendCryptoBytes(progress.IngressCursor, validServerHello);
        QuicTlsTranscriptStep repeatedStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, repeatedStep.Kind);
        Assert.Equal((ushort)0x0032, repeatedStep.AlertDescription);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, progress.Phase);
        Assert.True(progress.IsTerminalFailure);
        Assert.Equal((ushort)0x0032, progress.TerminalAlertDescription);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedNgtcp2ServerFlightWithSupportedGroupsEncryptedExtensionsAdvancesTranscript()
    {
        byte[] originalInitialDestinationConnectionId = Convert.FromHexString("006401FAF38454FB");
        byte[] protectedInitialPacket = Convert.FromHexString(
            "C50000000108CCAA9CFF197C1564129B8B232816BAA97AB485D9C59655AA1FD0F0008000009BA9D4D78359B979EC9DE214137D1FB8CFF74AB43276A1239EB40A7AC6537C56DC0599D2E4280C1066F1AC1D651DCC2B57C329C5A2CEB42EC233570B05063B19EB64A06E27953AA22AEA00917B8714784AD16234DFC0BBC3505AC11317F9BA7E503FC48386D7ED0F9106F87330A009362C3AEE5750700891F18CE41ABAE3E250330DCD0CC245E285F420C04306F17864C47AF7002F82D5BFAA207E93");
        byte[] protectedHandshakePacket = Convert.FromHexString(
            "E80000000108CCAA9CFF197C1564129B8B232816BAA97AB485D9C59655AA1FD0F0800002EB0C177A50FB6FAC9B00B19A2DA07A5B576A08E9BEBD33DB0342020E176BBE8372E8776B8990DC51CB48A1AB745250E2DE2A6A28514E7C93E265A6061A4CFBCB9DDADDCD57A773B0EFD16CCB6FD967CB4BB2165511FD2FD3AA3D1D9EA365BBCAAA0D64709B184C7594549039D8CE51A02BD4F935D1A34D53C9049B5ACDF03D152268C3E17CDC843540486B2676AD469C2F4A7DDBF4898A12F6BC59F5DFF29A4275A943CD0058F079D686485E8B4ADBD063CAC13ACB355C8CA75F05D104B41EEA6177D1C8EFB8759593566BC8F25EB00E0D3C69DA458B267FE5933F2F5AF2EB90D683448FCD350F1C37489954C98616364613543585C5D13BC5B5A1D0ECFC71096131F3FD60F9C7898B63D6F9C81003C95DDB7339C46AA1CE291B8AD8D0C938332F6AF4D0FED3AEB3B16D443CF4FB137476E3BE6F235A2CEA665FF5CB6B3DD944F4AB8AAA88F3CF9F47E6556581922144B5F77AB3BD1531C7E5B496E4C51B80FF771CC78236DBDBCB83C23B2DDD73DEE100024D5C561386A4955C1ECBD07F896B9E60C6D1E7B9327521595BF7C86C29EB655D0C95DE4104C45DA44890BD5DA77861F5E1E7F201AE98702F94D300D7BF9240C6423E77B378B9AF35FFFE04846F9192A9BBCB01ECB4F6143C5F659F3CDCE5F19DC5F9A3FD0679CDC3C602F10F42DAB96B4E73930D36401D866F3974163320D222D22168272A04F1F61F84604794DF3900842375D39075AA0630AEC3ACBA4E760C0B22C6F2B82D50AD8A229E24C2CE02B0FB00ECE3847C25E5E7C7A6A080261A96C169B83B117C64214C3303187B9F2A14A32DBDA6D2F7488ECBC4B5671B53435265B2AE989C67EBA7EFD6B7628D5CCDFBE723206C3B78CB7C3979CD6C6803ECCCB575AA6EE6DA11C98EB737DB63117FC673671D0A8CC0B267C6E4F63D82D00244594D779DEB71B5BE141CFA97C86387C3E86959B745402B8658A1D6C21E17E5FA31FAC9476A76FC157479A22744A001148E33070C5F0911034C9CE0B26B6DC41D2AD1BD878820AB7147C1E8ABD99904923CE98EBFCFA504BDEAFB");
        byte[] serverHandshakeTrafficSecret = Convert.FromHexString(
            "35CE5A2E82D42BD85204BF9673B4FFC5651B88D6E6C67F4E87AAE1014F9A96E8");

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            originalInitialDestinationConnectionId,
            out QuicInitialPacketProtection initialProtection));

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenInitialPacket(
            protectedInitialPacket,
            initialProtection,
            requireZeroTokenLength: true,
            out byte[] openedInitialPacket,
            out int initialPayloadOffset,
            out int initialPayloadLength));

        byte[] serverHello = ExtractFirstCryptoFrameData(
            openedInitialPacket.AsSpan(initialPayloadOffset, initialPayloadLength));

        Assert.True(TryCreateHandshakePacketProtectionMaterial(
            serverHandshakeTrafficSecret,
            out QuicTlsPacketProtectionMaterial handshakeProtectionMaterial));
        Assert.True(coordinator.TryOpenHandshakePacket(
            protectedHandshakePacket,
            handshakeProtectionMaterial,
            out byte[] openedHandshakePacket,
            out int handshakePayloadOffset,
            out int handshakePayloadLength));

        byte[] handshakeCrypto = ExtractFirstCryptoFrameData(
            openedHandshakePacket.AsSpan(handshakePayloadOffset, handshakePayloadLength));

        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        progress.AppendCryptoBytes(0, serverHello);
        QuicTlsTranscriptStep serverHelloStep = progress.Advance(QuicTlsRole.Client);
        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, serverHelloStep.Kind);

        progress.AppendCryptoBytes(progress.IngressCursor, handshakeCrypto);
        List<string> steps = [];
        while (true)
        {
            QuicTlsTranscriptStep step = progress.Advance(QuicTlsRole.Client);
            steps.Add($"{step.Kind}:{step.HandshakeMessageType}:{step.AlertDescription:X4}:{progress.Phase}");
            if (step.Kind is QuicTlsTranscriptStepKind.None or QuicTlsTranscriptStepKind.Fatal)
            {
                break;
            }
        }

        Assert.Equal(
            [
                "PeerTransportParametersStaged:EncryptedExtensions::PeerTransportParametersStaged",
                "Progressed:Certificate::PeerTransportParametersStaged",
                "Progressed:CertificateVerify::PeerTransportParametersStaged",
                "Progressed:Finished::Completed",
                "None:::Completed",
            ],
            steps);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, progress.Phase);
        Assert.False(progress.IsTerminalFailure);
    }

    private static QuicTransportParameters CreateClientTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 21,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreateServerTransportParameters()
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
        };
    }

    private static byte[] CreateClientHelloTranscript(QuicTransportParameters transportParameters)
    {
        byte[] supportedVersionsExtension = CreateClientSupportedVersionsExtension();
        byte[] keyShareExtension = CreateClientKeyShareExtension();
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Client);

        int extensionsLength = supportedVersionsExtension.Length
            + keyShareExtension.Length
            + transportParametersExtension.Length;
        byte[] body = new byte[43 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;

        CreateSequentialBytes(0x10, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;

        body[index++] = 0;

        WriteUInt16(body.AsSpan(index, 2), 2);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256);
        index += 2;

        body[index++] = 1;
        body[index++] = 0x00;

        WriteUInt16(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;
        supportedVersionsExtension.CopyTo(body.AsSpan(index));
        index += supportedVersionsExtension.Length;
        keyShareExtension.CopyTo(body.AsSpan(index));
        index += keyShareExtension.Length;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] CreateServerHelloTranscript(
        QuicTlsCipherSuite cipherSuite,
        bool includeTransportParametersExtension = false)
    {
        byte[] keyShare = CreateServerKeyShare();
        byte[] transportParametersExtension = includeTransportParametersExtension
            ? CreateTransportParametersExtension(CreateServerTransportParameters(), QuicTransportParameterRole.Server)
            : [];

        int supportedVersionsExtensionLength = 6;
        int keyShareExtensionLength = 2 + 2 + 2 + 2 + keyShare.Length;
        int extensionsLength = supportedVersionsExtensionLength + keyShareExtensionLength + transportParametersExtension.Length;
        byte[] body = new byte[40 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;

        CreateSequentialBytes(0x40, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;

        body[index++] = 0;
        WriteUInt16(body.AsSpan(index, 2), (ushort)cipherSuite);
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
        index += keyShare.Length;

        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
    }

    private static byte[] CreateServerKeyShare()
    {
        using ECDiffieHellman serverKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        serverKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(2),
        });

        ECParameters parameters = serverKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[1 + (2 * 32)];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    private static byte[] CreateClientSupportedVersionsExtension()
    {
        byte[] extension = new byte[7];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x002b);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), 3);
        index += 2;
        extension[index++] = 2;
        WriteUInt16(extension.AsSpan(index, 2), 0x0304);
        return extension;
    }

    private static byte[] CreateClientKeyShareExtension()
    {
        byte[] keyShare = CreateClientKeyShare();
        byte[] extension = new byte[2 + 2 + 2 + 2 + 2 + keyShare.Length];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x0033);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)(2 + 2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)(2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)QuicTlsNamedGroup.Secp256r1);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)keyShare.Length);
        index += 2;
        keyShare.CopyTo(extension.AsSpan(index, keyShare.Length));
        return extension;
    }

    private static byte[] CreateClientKeyShare()
    {
        using ECDiffieHellman clientKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        clientKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(1),
        });

        ECParameters parameters = clientKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[1 + (2 * 32)];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static byte[] CreateEncryptedExtensionsTranscript(
        QuicTransportParameters transportParameters,
        bool duplicateTransportParametersExtension = false,
        bool includeUnknownExtension = false,
        bool includeSupportedGroupsExtension = false,
        bool includeMalformedSupportedGroupsExtension = false)
    {
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Server);
        byte[] unknownExtension = includeUnknownExtension
            ? CreateUnknownExtension(0x1234, new byte[] { 0xAB })
            : Array.Empty<byte>();
        byte[] supportedGroupsExtension = includeSupportedGroupsExtension
            ? CreateSupportedGroupsExtension()
            : Array.Empty<byte>();
        byte[] malformedSupportedGroupsExtension = includeMalformedSupportedGroupsExtension
            ? CreateUnknownExtension(SupportedGroupsExtensionType, new byte[] { 0x00, 0x01, 0x00 })
            : Array.Empty<byte>();

        int extensionsLength = duplicateTransportParametersExtension
            ? transportParametersExtension.Length * 2
            : transportParametersExtension.Length;
        extensionsLength += unknownExtension.Length;
        extensionsLength += supportedGroupsExtension.Length;
        extensionsLength += malformedSupportedGroupsExtension.Length;

        byte[] body = new byte[2 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;
        transportParametersExtension.CopyTo(body.AsSpan(index));
        index += transportParametersExtension.Length;
        if (duplicateTransportParametersExtension)
        {
            transportParametersExtension.CopyTo(body.AsSpan(index));
            index += transportParametersExtension.Length;
        }

        if (includeUnknownExtension)
        {
            unknownExtension.CopyTo(body.AsSpan(index));
            index += unknownExtension.Length;
        }

        if (includeSupportedGroupsExtension)
        {
            supportedGroupsExtension.CopyTo(body.AsSpan(index));
            index += supportedGroupsExtension.Length;
        }

        if (includeMalformedSupportedGroupsExtension)
        {
            malformedSupportedGroupsExtension.CopyTo(body.AsSpan(index));
        }

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.EncryptedExtensions, body);
    }

    private static byte[] CreateCertificateTranscript()
    {
        byte[] certificateEntry = new byte[6];
        int index = 0;

        WriteUInt24(certificateEntry.AsSpan(index, 3), 1);
        index += 3;
        certificateEntry[index++] = 0x01;
        WriteUInt16(certificateEntry.AsSpan(index, 2), 0);

        byte[] body = new byte[1 + 3 + certificateEntry.Length];
        index = 0;

        body[index++] = 0;
        WriteUInt24(body.AsSpan(index, 3), certificateEntry.Length);
        index += 3;
        certificateEntry.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Certificate, body);
    }

    private static byte[] CreateCertificateVerifyTranscript()
    {
        byte[] body =
        [
            0x04,
            0x03,
            0x02,
            0x01,
        ];

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.CertificateVerify, body);
    }

    private static byte[] CreateFinishedTranscript(QuicTlsTranscriptHashAlgorithm transcriptHashAlgorithm)
    {
        int finishedLength = transcriptHashAlgorithm switch
        {
            QuicTlsTranscriptHashAlgorithm.Sha256 => 32,
            QuicTlsTranscriptHashAlgorithm.Sha384 => 48,
            _ => throw new ArgumentOutOfRangeException(nameof(transcriptHashAlgorithm)),
        };

        return WrapHandshakeMessage(
            QuicTlsHandshakeMessageType.Finished,
            CreateSequentialBytes(0xE0, finishedLength));
    }

    private static byte[] CreateMalformedEncryptedExtensionsTranscript()
    {
        byte[] transcript = CreateEncryptedExtensionsTranscript(CreateServerTransportParameters());
        ushort declaredExtensionsLength = (ushort)(transcript.Length - 4 - 2 + 1);
        WriteUInt16(transcript.AsSpan(4, 2), declaredExtensionsLength);
        return transcript;
    }

    private static byte[] CreateTransportParametersExtension(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            senderRole,
            encodedTransportParameters,
            out int bytesWritten));

        byte[] extension = new byte[4 + bytesWritten];
        WriteUInt16(extension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        WriteUInt16(extension.AsSpan(2, 2), (ushort)bytesWritten);
        encodedTransportParameters.AsSpan(0, bytesWritten).CopyTo(extension.AsSpan(4));
        return extension;
    }

    private static byte[] CreateUnknownExtension(ushort extensionType, ReadOnlySpan<byte> extensionValue)
    {
        byte[] extension = new byte[4 + extensionValue.Length];
        WriteUInt16(extension.AsSpan(0, 2), extensionType);
        WriteUInt16(extension.AsSpan(2, 2), (ushort)extensionValue.Length);
        extensionValue.CopyTo(extension.AsSpan(4));
        return extension;
    }

    private static byte[] CreateSupportedGroupsExtension()
    {
        byte[] extensionValue = new byte[6];
        WriteUInt16(extensionValue.AsSpan(0, 2), 4);
        WriteUInt16(extensionValue.AsSpan(2, 2), (ushort)QuicTlsNamedGroup.X25519);
        WriteUInt16(extensionValue.AsSpan(4, 2), (ushort)QuicTlsNamedGroup.Secp256r1);
        return CreateUnknownExtension(SupportedGroupsExtensionType, extensionValue);
    }

    private static byte[] ExtractFirstCryptoFrameData(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out _))
            {
                return cryptoFrame.CryptoData.ToArray();
            }

            Assert.Fail($"Unexpected captured payload frame at offset {offset}: 0x{remaining[0]:X2}.");
        }

        Assert.Fail("The captured payload did not contain a CRYPTO frame.");
        return [];
    }

    private static bool TryCreateHandshakePacketProtectionMaterial(
        ReadOnlySpan<byte> trafficSecret,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        byte[] aeadKey = HkdfExpandLabel(trafficSecret, "quic key"u8, [], 16);
        byte[] aeadIv = HkdfExpandLabel(trafficSecret, "quic iv"u8, [], 12);
        byte[] headerProtectionKey = HkdfExpandLabel(trafficSecret, "quic hp"u8, [], 16);
        if (!QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits usageLimits))
        {
            return false;
        }

        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            usageLimits,
            out material);
    }

    private static byte[] HkdfExpandLabel(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context,
        int length)
    {
        byte[] labelPrefix = "tls13 "u8.ToArray();
        byte[] hkdfLabel = new byte[2 + 1 + labelPrefix.Length + label.Length + 1 + context.Length];
        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel.AsSpan(0, 2), checked((ushort)length));
        hkdfLabel[2] = checked((byte)(labelPrefix.Length + label.Length));
        labelPrefix.CopyTo(hkdfLabel.AsSpan(3));
        label.CopyTo(hkdfLabel.AsSpan(3 + labelPrefix.Length));
        hkdfLabel[3 + labelPrefix.Length + label.Length] = checked((byte)context.Length);
        context.CopyTo(hkdfLabel.AsSpan(4 + labelPrefix.Length + label.Length));

        byte[] input = new byte[hkdfLabel.Length + 1];
        hkdfLabel.CopyTo(input, 0);
        input[^1] = 1;

        return HMACSHA256.HashData(secret, input)[..length];
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, 3), body.Length);
        body.CopyTo(transcript.AsSpan(4));
        return transcript;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }

    private static void WriteUInt16(Span<byte> destination, ushort value)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination, value);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }
}

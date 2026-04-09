namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0107")]
public sealed class REQ_QUIC_CRT_0107
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleConsumesAnOrderedHandshakeTranscriptAndStagesPeerTransportParametersFromEncryptedExtensions()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] serverHello = CreateServerHelloTranscript(QuicTlsCipherSuite.TlsAes256GcmSha384);
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(CreateServerTransportParameters());
        byte[] certificate = CreateCertificateTranscript();
        byte[] certificateVerify = CreateCertificateVerifyTranscript();
        byte[] finished = CreateFinishedTranscript(QuicTlsTranscriptHashAlgorithm.Sha384);

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
        Assert.Equal(QuicTlsCipherSuite.TlsAes256GcmSha384, serverHelloStep.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha384, serverHelloStep.TranscriptHashAlgorithm);
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
        Assert.Equal(QuicTlsCipherSuite.TlsAes256GcmSha384, progress.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha384, progress.TranscriptHashAlgorithm);
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
        Assert.Equal(QuicTlsTranscriptPhase.Completed, clientHelloStep.TranscriptPhase);
        Assert.NotNull(clientHelloStep.TransportParameters);
        Assert.Equal(21UL, clientHelloStep.TransportParameters!.MaxIdleTimeout);
        Assert.True(clientHelloStep.TransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, clientHelloStep.TransportParameters.InitialSourceConnectionId);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, progress.Phase);
        Assert.NotNull(progress.StagedPeerTransportParameters);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, progress.HandshakeMessageType);
        Assert.Equal((uint)(clientHello.Length - 4), progress.HandshakeMessageLength);
        Assert.Null(progress.SelectedCipherSuite);
        Assert.Null(progress.TranscriptHashAlgorithm);
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
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Client);

        byte[] body = new byte[43 + transportParametersExtension.Length];
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

        WriteUInt16(body.AsSpan(index, 2), (ushort)transportParametersExtension.Length);
        index += 2;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] CreateServerHelloTranscript(
        QuicTlsCipherSuite cipherSuite,
        bool includeTransportParametersExtension = false)
    {
        byte[] transportParametersExtension = includeTransportParametersExtension
            ? CreateTransportParametersExtension(CreateServerTransportParameters(), QuicTransportParameterRole.Server)
            : [];

        byte[] body = new byte[40 + transportParametersExtension.Length];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;

        CreateSequentialBytes(0x40, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;

        body[index++] = 0;
        WriteUInt16(body.AsSpan(index, 2), (ushort)cipherSuite);
        index += 2;

        body[index++] = 0x00;

        WriteUInt16(body.AsSpan(index, 2), (ushort)transportParametersExtension.Length);
        index += 2;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
    }

    private static byte[] CreateEncryptedExtensionsTranscript(
        QuicTransportParameters transportParameters,
        bool duplicateTransportParametersExtension = false)
    {
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Server);

        int extensionsLength = duplicateTransportParametersExtension
            ? transportParametersExtension.Length * 2
            : transportParametersExtension.Length;

        byte[] body = new byte[2 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;
        transportParametersExtension.CopyTo(body.AsSpan(index));
        if (duplicateTransportParametersExtension)
        {
            transportParametersExtension.CopyTo(body.AsSpan(index + transportParametersExtension.Length));
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

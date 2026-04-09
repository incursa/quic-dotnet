namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S8-0002")]
public sealed class REQ_QUIC_RFC9001_S8_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AuthenticatedTransportParametersAreCommittedAsSnapshots()
    {
        QuicTransportParameters sourceParameters = new()
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [203, 0, 113, 7],
                IPv4Port = 9443,
                IPv6Address = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
                IPv6Port = 9553,
                ConnectionId = [0x44, 0x55],
                StatelessResetToken = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F],
            },
        };

        Span<byte> encodedParameters = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            sourceParameters,
            QuicTransportParameterRole.Server,
            encodedParameters,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedParameters));

        QuicTransportTlsBridgeState bridge = new();
        Assert.False(bridge.CanCommitPeerTransportParameters());
        Assert.False(bridge.CanEmitHandshakeConfirmed());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: 48,
            TransportParameters: parsedParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.CanCommitPeerTransportParameters());
        Assert.False(bridge.CanEmitHandshakeConfirmed());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersAuthenticated,
            TransportParameters: parsedParameters)));
        Assert.False(bridge.CanCommitPeerTransportParameters());
        Assert.False(bridge.CanEmitHandshakeConfirmed());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(bridge.CanEmitHandshakeConfirmed());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.HandshakeConfirmed)));
        Assert.False(bridge.CanEmitHandshakeConfirmed());

        sourceParameters.InitialSourceConnectionId![0] = 0xFF;
        parsedParameters.InitialSourceConnectionId![0] = 0xEE;
        parsedParameters.PreferredAddress!.ConnectionId[0] = 0xDD;
        parsedParameters.PreferredAddress.StatelessResetToken[0] = 0xCC;

        Assert.True(bridge.PeerTransportParametersAuthenticated);
        Assert.True(bridge.HandshakeConfirmed);
        Assert.NotSame(parsedParameters, bridge.PeerTransportParameters);
        Assert.Equal(30UL, bridge.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(bridge.PeerTransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, bridge.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(new byte[] { 0x44, 0x55 }, bridge.PeerTransportParameters.PreferredAddress!.ConnectionId);
        Assert.Equal(new byte[] { 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F }, bridge.PeerTransportParameters.PreferredAddress.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AuthenticatedTransportParametersAreRejectedBeforeTranscriptProgressIsStaged()
    {
        QuicTransportParameters sourceParameters = new()
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
        };

        Span<byte> encodedParameters = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            sourceParameters,
            QuicTransportParameterRole.Server,
            encodedParameters,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedParameters));

        QuicTransportTlsBridgeState bridge = new();
        Assert.False(bridge.CanCommitPeerTransportParameters());
        Assert.False(bridge.CanEmitHandshakeConfirmed());
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersAuthenticated,
            TransportParameters: parsedParameters)));
        Assert.False(bridge.PeerTransportParametersAuthenticated);
        Assert.Null(bridge.PeerTransportParameters);
        Assert.False(bridge.CanCommitPeerTransportParameters());
        Assert.False(bridge.CanEmitHandshakeConfirmed());
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.HandshakeConfirmed)));
        Assert.False(bridge.HandshakeConfirmed);

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: 48,
            TransportParameters: parsedParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.CanCommitPeerTransportParameters());
        Assert.False(bridge.CanEmitHandshakeConfirmed());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersAuthenticated,
            TransportParameters: parsedParameters)));
        Assert.False(bridge.CanCommitPeerTransportParameters());
        Assert.False(bridge.CanEmitHandshakeConfirmed());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(bridge.CanEmitHandshakeConfirmed());
        Assert.True(bridge.PeerTransportParametersAuthenticated);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverCommitsAndConfirmsPeerTransportParametersOnlyWhenTheBridgeGateOpens()
    {
        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        }));

        byte[] encodedParameters = CreateFormattedTransportParameters(new QuicTransportParameters
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
        });
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedParameters,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters peerParameters));
        byte[] transcript = CreateClientHandshakeTranscript(peerParameters);

        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            transcript[..5]);

        Assert.Empty(firstUpdates);
        Assert.False(driver.State.PeerTransportParametersAuthenticated);
        Assert.False(driver.State.HandshakeConfirmed);
        Assert.False(driver.State.CanCommitPeerTransportParameters());
        Assert.False(driver.State.CanEmitHandshakeConfirmed());
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, driver.State.HandshakeTranscriptPhase);

        IReadOnlyList<QuicTlsStateUpdate> secondUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            transcript[5..]);

        Assert.Equal(2, secondUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, secondUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, secondUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, secondUpdates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes256GcmSha384, secondUpdates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha384, secondUpdates[0].TranscriptHashAlgorithm);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, secondUpdates[1].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, secondUpdates[1].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, secondUpdates[1].TranscriptPhase);
        Assert.NotNull(secondUpdates[1].TransportParameters);
        Assert.False(driver.State.PeerTransportParametersAuthenticated);
        Assert.False(driver.State.HandshakeConfirmed);
        Assert.True(driver.State.CanCommitPeerTransportParameters());
        Assert.False(driver.State.CanEmitHandshakeConfirmed());
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, driver.State.HandshakeTranscriptPhase);

        IReadOnlyList<QuicTlsStateUpdate> completedUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.Completed,
            QuicTlsHandshakeMessageType.Finished,
            handshakeMessageLength: 48);
        Assert.Single(completedUpdates);
        Assert.False(driver.State.CanEmitHandshakeConfirmed());

        IReadOnlyList<QuicTlsStateUpdate> authUpdates = driver.CommitPeerTransportParameters(new QuicTransportParameters
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
        });
        Assert.Single(authUpdates);
        Assert.False(driver.State.CanCommitPeerTransportParameters());
        Assert.True(driver.State.CanEmitHandshakeConfirmed());

        IReadOnlyList<QuicTlsStateUpdate> confirmUpdates = driver.PublishHandshakeConfirmed();
        Assert.Single(confirmUpdates);
        Assert.Equal(QuicTlsUpdateKind.HandshakeConfirmed, confirmUpdates[0].Kind);
        Assert.True(driver.State.HandshakeConfirmed);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, driver.State.HandshakeTranscriptPhase);
        Assert.False(driver.State.CanCommitPeerTransportParameters());
        Assert.False(driver.State.CanEmitHandshakeConfirmed());
        Assert.Equal(30UL, driver.State.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(driver.State.PeerTransportParameters.DisableActiveMigration);
    }

    private static byte[] CreateFormattedTransportParameters(QuicTransportParameters transportParameters)
    {
        byte[] encodedParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Server,
            encodedParameters,
            out int bytesWritten));

        return encodedParameters[..bytesWritten];
    }

    private static byte[] CreateEncryptedExtensionsTranscript(ReadOnlySpan<byte> encodedTransportParameters)
    {
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parameters));

        byte[] transcript = new byte[512];
        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicTransportParametersMessage(
            parameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int bytesWritten));

        Array.Resize(ref transcript, bytesWritten);
        return transcript;
    }

    private static byte[] CreateClientHandshakeTranscript(QuicTransportParameters transportParameters)
    {
        byte[] serverHello = CreateServerHelloTranscript();
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(transportParameters));

        byte[] transcript = new byte[serverHello.Length + encryptedExtensions.Length];
        serverHello.CopyTo(transcript.AsSpan(0, serverHello.Length));
        encryptedExtensions.CopyTo(transcript.AsSpan(serverHello.Length));
        return transcript;
    }

    private static byte[] CreateServerHelloTranscript()
    {
        byte[] body = new byte[40];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;

        for (int i = 0; i < 32; i++)
        {
            body[index + i] = unchecked((byte)(0x40 + i));
        }

        index += 32;
        body[index++] = 0;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsCipherSuite.TlsAes256GcmSha384);
        index += 2;
        body[index++] = 0x00;
        WriteUInt16(body.AsSpan(index, 2), 0);

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
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
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination, value);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }
}

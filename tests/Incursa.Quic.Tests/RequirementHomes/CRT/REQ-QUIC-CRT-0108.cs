using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0108")]
public sealed class REQ_QUIC_CRT_0108
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ManagedClientRoleKeySchedulePublishesHandshakeKeysAndVerifiesPeerFinished()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTlsKeySchedule schedule = new(localHandshakePrivateKey);
        QuicTransportTlsBridgeState bridge = new();
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();

        Assert.False(schedule.HandshakeSecretsDerived);
        Assert.False(schedule.TryGetExpectedPeerFinishedVerifyData(out _));
        Assert.False(bridge.HandshakeKeysAvailable);

        QuicTlsTranscriptStep serverHelloStep = CreateServerHelloStep(
            QuicTlsCipherSuite.TlsAes128GcmSha256,
            CreateServerKeyShare(0x02));

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = schedule.ProcessTranscriptStep(serverHelloStep);
        Assert.Equal(3, serverHelloUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, serverHelloUpdates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, serverHelloUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, serverHelloUpdates[2].Kind);

        Assert.True(bridge.TryApply(serverHelloUpdates[0]));
        Assert.False(bridge.HandshakeKeysAvailable);
        Assert.True(bridge.TryApply(serverHelloUpdates[1]));
        Assert.False(bridge.HandshakeKeysAvailable);
        Assert.True(bridge.TryApply(serverHelloUpdates[2]));
        Assert.True(bridge.HandshakeKeysAvailable);
        Assert.True(bridge.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial openMaterial));
        Assert.True(bridge.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial protectMaterial));
        Assert.True(openMaterial.Matches(serverHelloUpdates[0].PacketProtectionMaterial!.Value));
        Assert.True(protectMaterial.Matches(serverHelloUpdates[1].PacketProtectionMaterial!.Value));
        Assert.True(schedule.HandshakeSecretsDerived);

        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] serverHelloOnlyVerifyData));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep()));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateVerifyStep()));
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] finishedVerifyData));
        Assert.False(serverHelloOnlyVerifyData.SequenceEqual(finishedVerifyData));

        QuicTlsTranscriptStep finishedStep = CreateFinishedStep(finishedVerifyData);
        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = schedule.ProcessTranscriptStep(finishedStep);

        Assert.Single(finishedUpdates);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[0].Kind);
        Assert.True(schedule.PeerFinishedVerified);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnsupportedServerHelloCipherSuiteFailsDeterministically()
    {
        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));

        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            CreateServerHelloStep(
                QuicTlsCipherSuite.TlsAes256GcmSha384,
                CreateServerKeyShare(0x02)));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.False(schedule.HandshakeSecretsDerived);
        Assert.False(schedule.TryGetExpectedPeerFinishedVerifyData(out _));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(CreateServerTransportParameters())));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedServerHelloKeyShareFailsDeterministically()
    {
        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));
        byte[] malformedKeyShare = CreateServerKeyShare(0x02)[..^1];

        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            CreateServerHelloStep(
                QuicTlsCipherSuite.TlsAes128GcmSha256,
                malformedKeyShare));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.False(schedule.HandshakeSecretsDerived);
        Assert.False(schedule.TryGetExpectedPeerFinishedVerifyData(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TranscriptHashDrivenSecretDerivationIsDeterministic()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();

        QuicTlsKeySchedule firstSchedule = new(localHandshakePrivateKey);
        QuicTlsKeySchedule secondSchedule = new(localHandshakePrivateKey);
        QuicTransportTlsBridgeState firstBridge = new();
        QuicTransportTlsBridgeState secondBridge = new();

        QuicTlsTranscriptStep serverHelloStep = CreateServerHelloStep(
            QuicTlsCipherSuite.TlsAes128GcmSha256,
            CreateServerKeyShare(0x02));

        IReadOnlyList<QuicTlsStateUpdate> firstServerHelloUpdates = firstSchedule.ProcessTranscriptStep(serverHelloStep);
        IReadOnlyList<QuicTlsStateUpdate> secondServerHelloUpdates = secondSchedule.ProcessTranscriptStep(serverHelloStep);

        Assert.Equal(firstServerHelloUpdates.Count, secondServerHelloUpdates.Count);
        Assert.Equal(3, firstServerHelloUpdates.Count);
        Assert.True(firstBridge.TryApply(firstServerHelloUpdates[0]));
        Assert.True(secondBridge.TryApply(secondServerHelloUpdates[0]));
        Assert.True(firstBridge.TryApply(firstServerHelloUpdates[1]));
        Assert.True(secondBridge.TryApply(secondServerHelloUpdates[1]));
        Assert.True(firstBridge.TryApply(firstServerHelloUpdates[2]));
        Assert.True(secondBridge.TryApply(secondServerHelloUpdates[2]));

        Assert.True(firstBridge.HandshakeKeysAvailable);
        Assert.True(secondBridge.HandshakeKeysAvailable);
        Assert.True(firstBridge.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial firstOpenMaterial));
        Assert.True(secondBridge.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial secondOpenMaterial));
        Assert.True(firstBridge.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial firstProtectMaterial));
        Assert.True(secondBridge.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial secondProtectMaterial));
        Assert.True(firstOpenMaterial.Matches(secondOpenMaterial));
        Assert.True(firstProtectMaterial.Matches(secondProtectMaterial));

        Assert.Empty(firstSchedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(firstSchedule.ProcessTranscriptStep(CreateCertificateStep()));
        Assert.Empty(firstSchedule.ProcessTranscriptStep(CreateCertificateVerifyStep()));
        Assert.Empty(secondSchedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(secondSchedule.ProcessTranscriptStep(CreateCertificateStep()));
        Assert.Empty(secondSchedule.ProcessTranscriptStep(CreateCertificateVerifyStep()));

        Assert.True(firstSchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] firstFinishedVerifyData));
        Assert.True(secondSchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] secondFinishedVerifyData));
        Assert.True(firstFinishedVerifyData.SequenceEqual(secondFinishedVerifyData));
    }

    private static QuicTlsTranscriptStep CreateServerHelloStep(
        QuicTlsCipherSuite cipherSuite,
        byte[] keyShare)
    {
        byte[] transcriptBytes = CreateServerHelloTranscript(cipherSuite, keyShare);
        QuicTlsTranscriptHashAlgorithm transcriptHashAlgorithm = cipherSuite switch
        {
            QuicTlsCipherSuite.TlsAes128GcmSha256 => QuicTlsTranscriptHashAlgorithm.Sha256,
            QuicTlsCipherSuite.TlsAes256GcmSha384 => QuicTlsTranscriptHashAlgorithm.Sha384,
            _ => throw new ArgumentOutOfRangeException(nameof(cipherSuite)),
        };

        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            SelectedCipherSuite: cipherSuite,
            TranscriptHashAlgorithm: transcriptHashAlgorithm,
            NamedGroup: QuicTlsNamedGroup.Secp256r1,
            KeyShare: keyShare,
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

    private static QuicTlsTranscriptStep CreateCertificateStep()
    {
        byte[] transcriptBytes = CreateCertificateTranscript();
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Certificate,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateCertificateVerifyStep()
    {
        byte[] transcriptBytes = CreateCertificateVerifyTranscript();
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateFinishedStep(ReadOnlySpan<byte> verifyData)
    {
        byte[] transcriptBytes = CreateFinishedTranscript(verifyData.ToArray());
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: (uint)verifyData.Length,
            HandshakeMessageBytes: transcriptBytes);
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
            ActiveConnectionIdLimit = 4,
        };
    }

    private static byte[] CreateServerHelloTranscript(
        QuicTlsCipherSuite cipherSuite,
        byte[] keyShare)
    {
        int extensionsLength = 6 + 4 + 2 + 2 + keyShare.Length;
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

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
    }

    private static byte[] CreateServerKeyShare(byte scalar = 0x02)
    {
        using ECDiffieHellman serverKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        serverKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(scalar),
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
        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicTransportParametersMessage(
            parsedTransportParameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int messageBytesWritten));

        Array.Resize(ref transcript, messageBytesWritten);
        return transcript;
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

    private static byte[] CreateFinishedTranscript(byte[] verifyData)
    {
        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Finished, verifyData);
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, 3), body.Length);
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

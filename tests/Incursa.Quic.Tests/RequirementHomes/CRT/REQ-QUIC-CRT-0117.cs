using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0117")]
public sealed class REQ_QUIC_CRT_0117
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleDriverVerifiesInboundClientFinishedAfterTheFullLocalFlight()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        (byte[] clientHelloTranscript, _) = CreateServerRoleClientHello(peerTransportParameters);
        byte[] localLeafCertificateDer = CreateLocalLeafCertificateDer(localSigningPrivateKey);
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> clientHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHelloTranscript);

        Assert.Equal(9, clientHelloUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, clientHelloUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, clientHelloUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, clientHelloUpdates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, clientHelloUpdates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, clientHelloUpdates[0].TranscriptHashAlgorithm);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, clientHelloUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, clientHelloUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, clientHelloUpdates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, clientHelloUpdates[4].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, clientHelloUpdates[5].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, clientHelloUpdates[6].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, clientHelloUpdates[7].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, clientHelloUpdates[8].Kind);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, driver.State.HandshakeTranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, driver.State.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, driver.State.TranscriptHashAlgorithm);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);

        FieldInfo keyScheduleField = typeof(QuicTlsTransportBridgeDriver).GetField(
            "keySchedule",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        QuicTlsKeySchedule driverKeySchedule = (QuicTlsKeySchedule)keyScheduleField.GetValue(driver)!;
        Assert.True(driverKeySchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] expectedFinishedVerifyData));

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateFinishedTranscript(expectedFinishedVerifyData));

        Assert.Equal(
            $"{QuicTlsUpdateKind.TranscriptProgressed},{QuicTlsUpdateKind.PeerFinishedVerified},{QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted}",
            string.Join(",", finishedUpdates.Select(update => update.Kind)));
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, finishedUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, finishedUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, finishedUpdates[0].TranscriptPhase);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted, finishedUpdates[2].Kind);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.PeerCertificateVerifyVerified);
        Assert.False(driver.State.PeerCertificatePolicyAccepted);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, driver.State.HandshakeTranscriptPhase);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, driver.State.HandshakeMessageType);
        Assert.False(driver.State.PeerTransportParametersCommitted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDriverRejectsInboundClientFinishedBeforeTheFullLocalFlightExists()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        (byte[] clientHelloTranscript, QuicTlsTranscriptStep clientHelloStep) = CreateServerRoleClientHello(peerTransportParameters);

        QuicTlsKeySchedule schedule = new(QuicTlsRole.Server, localHandshakePrivateKey);
        IReadOnlyList<QuicTlsStateUpdate> partialServerFlightUpdates = schedule.ProcessTranscriptStep(
            clientHelloStep,
            localTransportParameters);

        Assert.Equal(5, partialServerFlightUpdates.Count);
        Assert.False(schedule.TryGetExpectedPeerFinishedVerifyData(out _));

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.Single(driver.StartHandshake(localTransportParameters));
        IReadOnlyList<QuicTlsStateUpdate> clientHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHelloTranscript);

        Assert.Equal(6, clientHelloUpdates.Count);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, driver.State.HandshakeTranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, driver.State.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, driver.State.TranscriptHashAlgorithm);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);

        IReadOnlyList<QuicTlsStateUpdate> prematureFinishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateFinishedTranscript(CreateSequentialBytes(0x80, 32)));

        Assert.Equal(2, prematureFinishedUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, prematureFinishedUpdates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, prematureFinishedUpdates[1].Kind);
        Assert.Equal((ushort)0x0032, prematureFinishedUpdates[1].AlertDescription);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(CreateClientTransportParameters()));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDriverRejectsMalformedOrMismatchedInboundClientFinishedDeterministically()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        (byte[] clientHelloTranscript, _) = CreateServerRoleClientHello(peerTransportParameters);
        byte[] localLeafCertificateDer = CreateLocalLeafCertificateDer(localSigningPrivateKey);

        QuicTlsTransportBridgeDriver malformedDriver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        Assert.Single(malformedDriver.StartHandshake(localTransportParameters));
        Assert.Equal(9, malformedDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHelloTranscript).Count);

        FieldInfo malformedKeyScheduleField = typeof(QuicTlsTransportBridgeDriver).GetField(
            "keySchedule",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        QuicTlsKeySchedule malformedDriverKeySchedule = (QuicTlsKeySchedule)malformedKeyScheduleField.GetValue(malformedDriver)!;
        Assert.True(malformedDriverKeySchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] malformedExpectedFinishedVerifyData));

        byte[] malformedFinishedTranscript = CreateFinishedTranscript(malformedExpectedFinishedVerifyData);
        WriteUInt24(malformedFinishedTranscript.AsSpan(1, 3), checked((int)malformedExpectedFinishedVerifyData.Length - 1));
        IReadOnlyList<QuicTlsStateUpdate> malformedUpdates = malformedDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            malformedFinishedTranscript);

        Assert.Single(malformedUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, malformedUpdates[0].Kind);
        Assert.Equal((ushort)0x0032, malformedUpdates[0].AlertDescription);
        Assert.True(malformedDriver.State.IsTerminal);
        Assert.False(malformedDriver.State.PeerFinishedVerified);

        QuicTlsTransportBridgeDriver mismatchedDriver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        Assert.Single(mismatchedDriver.StartHandshake(localTransportParameters));
        Assert.Equal(9, mismatchedDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHelloTranscript).Count);

        FieldInfo mismatchedKeyScheduleField = typeof(QuicTlsTransportBridgeDriver).GetField(
            "keySchedule",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        QuicTlsKeySchedule mismatchedDriverKeySchedule = (QuicTlsKeySchedule)mismatchedKeyScheduleField.GetValue(mismatchedDriver)!;
        Assert.True(mismatchedDriverKeySchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] mismatchedExpectedFinishedVerifyData));

        byte[] mismatchedFinishedTranscript = CreateFinishedTranscript(mismatchedExpectedFinishedVerifyData);
        mismatchedFinishedTranscript[^1] ^= 0x80;

        IReadOnlyList<QuicTlsStateUpdate> mismatchedUpdates = mismatchedDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            mismatchedFinishedTranscript);

        Assert.Equal(2, mismatchedUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, mismatchedUpdates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, mismatchedUpdates[1].Kind);
        Assert.Equal((ushort)0x0033, mismatchedUpdates[1].AlertDescription);
        Assert.True(mismatchedDriver.State.IsTerminal);
        Assert.False(mismatchedDriver.State.PeerFinishedVerified);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDriverRejectsRepeatedOrConflictingInboundClientFinishedProgressionDeterministically()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        (byte[] clientHelloTranscript, _) = CreateServerRoleClientHello(peerTransportParameters);
        byte[] localLeafCertificateDer = CreateLocalLeafCertificateDer(localSigningPrivateKey);

        QuicTlsTransportBridgeDriver repeatedDriver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        Assert.Single(repeatedDriver.StartHandshake(localTransportParameters));
        Assert.Equal(9, repeatedDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHelloTranscript).Count);
        FieldInfo repeatedKeyScheduleField = typeof(QuicTlsTransportBridgeDriver).GetField(
            "keySchedule",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        QuicTlsKeySchedule repeatedDriverKeySchedule = (QuicTlsKeySchedule)repeatedKeyScheduleField.GetValue(repeatedDriver)!;
        Assert.True(repeatedDriverKeySchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] repeatedFinishedVerifyData));
        byte[] finishedTranscript = CreateFinishedTranscript(repeatedFinishedVerifyData);
        Assert.Equal(3, repeatedDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript).Count);

        IReadOnlyList<QuicTlsStateUpdate> repeatedUpdates = repeatedDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);

        Assert.Single(repeatedUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, repeatedUpdates[0].Kind);
        Assert.Equal((ushort)0x0010, repeatedUpdates[0].AlertDescription);
        Assert.True(repeatedDriver.State.IsTerminal);

        QuicTlsTransportBridgeDriver conflictingDriver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        Assert.Single(conflictingDriver.StartHandshake(localTransportParameters));
        Assert.Equal(9, conflictingDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHelloTranscript).Count);
        FieldInfo conflictingKeyScheduleField = typeof(QuicTlsTransportBridgeDriver).GetField(
            "keySchedule",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        QuicTlsKeySchedule conflictingDriverKeySchedule = (QuicTlsKeySchedule)conflictingKeyScheduleField.GetValue(conflictingDriver)!;
        Assert.True(conflictingDriverKeySchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] conflictingFinishedVerifyData));
        byte[] conflictingFinishedTranscript = CreateFinishedTranscript(conflictingFinishedVerifyData);
        Assert.Equal(3, conflictingDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            conflictingFinishedTranscript).Count);

        conflictingFinishedTranscript[^1] ^= 0x01;

        IReadOnlyList<QuicTlsStateUpdate> conflictingUpdates = conflictingDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            conflictingFinishedTranscript);

        Assert.Single(conflictingUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, conflictingUpdates[0].Kind);
        Assert.Equal((ushort)0x0010, conflictingUpdates[0].AlertDescription);
        Assert.True(conflictingDriver.State.IsTerminal);
    }

    private static byte[] CreateLocalLeafCertificateDer(byte[] localSigningPrivateKey)
    {
        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        return QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);
    }

    private static (byte[] ClientHelloTranscript, QuicTlsTranscriptStep ClientHelloStep) CreateServerRoleClientHello(
        QuicTransportParameters peerTransportParameters)
    {
        byte[] clientHello = CreateClientHelloTranscript(peerTransportParameters);
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Server);
        progress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);

        Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, clientHelloStep.Kind);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, clientHelloStep.TranscriptPhase);
        return (clientHello, clientHelloStep);
    }

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
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

    private static byte[] CreateTransportParametersExtension(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            senderRole,
            encodedTransportParameters,
            out int transportParametersBytesWritten));

        byte[] extension = new byte[4 + transportParametersBytesWritten];
        WriteUInt16(extension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        WriteUInt16(extension.AsSpan(2, 2), (ushort)transportParametersBytesWritten);
        encodedTransportParameters.AsSpan(0, transportParametersBytesWritten).CopyTo(extension.AsSpan(4));
        return extension;
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
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }
}

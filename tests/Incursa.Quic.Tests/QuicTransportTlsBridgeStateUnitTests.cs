// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicTransportTlsBridgeStateUnitTests
{
    [Fact]
    public void TryCommitLocalTransportParameters_ClonesVersionInformationSnapshot()
    {
        QuicTransportTlsBridgeState state = new();
        uint[] availableVersions =
        [
            QuicVersionNegotiation.Version2,
            QuicVersionNegotiation.Version1,
        ];

        QuicTransportParameters parameters = new()
        {
            VersionInformation = new QuicVersionInformation
            {
                ChosenVersion = QuicVersionNegotiation.Version2,
                AvailableVersions = availableVersions,
            },
        };

        Assert.True(state.TryCommitLocalTransportParameters(parameters));

        parameters.VersionInformation!.ChosenVersion = QuicVersionNegotiation.Version1;
        parameters.VersionInformation.AvailableVersions[0] = 0x11223344;

        Assert.NotNull(state.LocalTransportParameters);
        Assert.NotNull(state.LocalTransportParameters!.VersionInformation);
        Assert.Equal(QuicVersionNegotiation.Version2, state.LocalTransportParameters!.VersionInformation!.ChosenVersion);
        Assert.Equal(QuicVersionNegotiation.Version2, state.LocalTransportParameters!.VersionInformation!.AvailableVersions[0]);
        Assert.Equal(QuicVersionNegotiation.Version1, state.LocalTransportParameters!.VersionInformation!.AvailableVersions[1]);
    }

    private static QuicTlsPacketProtectionMaterial CreateOneRttProtectionMaterial()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            new byte[16],
            new byte[12],
            new byte[16],
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));
        return material;
    }

    [Fact]
    public void OneRttSendAuthorized_ReturnsFalseWhenNoKeysOrMaterial()
    {
        QuicTransportTlsBridgeState state = new();
        Assert.False(state.OneRttSendAuthorized);
    }

    [Fact]
    public void OneRttSendAuthorized_ReturnsTrueWhenFullyReady()
    {
        QuicTransportTlsBridgeState state = new();
        state.SetPeerFinishedVerifiedForTests(true);
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.True(state.OneRttSendAuthorized);
    }

    [Fact]
    public void OneRttSendAuthorized_ReturnsFalseWhenTerminal()
    {
        QuicTransportTlsBridgeState state = new();
        state.SetPeerFinishedVerifiedForTests(true);
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.FatalAlert,
            AlertDescription: 0x0032)));
        Assert.True(state.IsTerminal);
        Assert.False(state.OneRttSendAuthorized);
    }

    [Fact]
    public void OneRttSendAuthorized_ReturnsFalseBeforePeerFinishedVerified()
    {
        QuicTransportTlsBridgeState state = new();
        Assert.False(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.False(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.False(state.OneRttSendAuthorized);
    }

    [Fact]
    public void OneRttReceiveAuthorized_ReturnsFalseWhenNoKeysOrMaterial()
    {
        QuicTransportTlsBridgeState state = new();
        Assert.False(state.OneRttReceiveAuthorized);
    }

    [Fact]
    public void OneRttReceiveAuthorized_ReturnsTrueWhenFullyReady()
    {
        QuicTransportTlsBridgeState state = new();
        state.SetPeerFinishedVerifiedForTests(true);
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.True(state.OneRttReceiveAuthorized);
    }

    [Fact]
    public void OneRttReceiveAuthorized_ReturnsFalseWhenTerminal()
    {
        QuicTransportTlsBridgeState state = new();
        state.SetPeerFinishedVerifiedForTests(true);
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.FatalAlert,
            AlertDescription: 0x0032)));
        Assert.True(state.IsTerminal);
        Assert.False(state.OneRttReceiveAuthorized);
    }

    [Fact]
    public void OneRttReceiveAuthorized_ReturnsFalseBeforePeerFinishedVerified()
    {
        QuicTransportTlsBridgeState state = new();
        Assert.False(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.False(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.False(state.OneRttReceiveAuthorized);
    }

    [Fact]
    public void OneRttSendAuthorized_ZeroRttMaterialDoesNotEnableSend()
    {
        QuicTransportTlsBridgeState state = new();

        // Zero-Rtt material should not satisfy the 1-RTT send guard.
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.ZeroRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            new byte[16],
            new byte[12],
            new byte[16],
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial zeroRttMaterial));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: zeroRttMaterial)));
        Assert.False(state.OneRttSendAuthorized);
        Assert.False(state.OneRttReceiveAuthorized);
    }

    [Fact]
    public void TryDiscardCompletedHandshakeMaterial_IsIdempotentOnFreshSchedule()
    {
        QuicTlsKeySchedule schedule = new();
        schedule.TryDiscardCompletedHandshakeMaterial();
        Assert.False(schedule.HandshakeSecretsDerived);
        Assert.False(schedule.PeerFinishedVerified);
    }

    [Fact]
    public void TryDiscardCompletedHandshakeMaterial_ClearsHandshakeTrafficSecrets()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTlsKeySchedule schedule = new(localHandshakePrivateKey);

        Assert.True(schedule.TryCreateClientHello(localTransportParameters, out byte[] clientHello));
        schedule.AppendLocalHandshakeMessage(clientHello);

        byte[] serverHello = CreateServerHelloBytes();
        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = schedule.ProcessTranscriptStep(
            new QuicTlsTranscriptStep(
                QuicTlsTranscriptStepKind.Progressed,
                TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage,
                HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
                HandshakeMessageLength: (uint)(serverHello.Length - 4),
                SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                NamedGroup: QuicTlsNamedGroup.Secp256r1,
                KeyShare: CreateServerKeyShare(),
                HandshakeMessageBytes: serverHello));
        Assert.NotEmpty(serverHelloUpdates);
        Assert.True(schedule.HandshakeSecretsDerived);

        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out _));

        schedule.TryDiscardCompletedHandshakeMaterial();

        Assert.False(schedule.TryGetExpectedPeerFinishedVerifyData(out _));
        Assert.True(schedule.TryCopyHandshakeTranscriptBytes(Span<byte>.Empty, out int bytesWritten));
        Assert.Equal(0, bytesWritten);
        Assert.False(schedule.TryGetPeerLeafCertificateSha256Fingerprint(out _));
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static byte[] CreateServerHelloBytes()
    {
        byte[] serverRandom = System.Security.Cryptography.SHA256.HashData("incursa.quic.server-random"u8);
        byte[] sessionId = [0x01, 0x02];
        byte[] keyShare = CreateServerKeyShare();
        int bodyLength = 2 + 32 + 1 + sessionId.Length + 2 + 1 + 2
            + (2 + 2 + 2)          // supported_versions
            + (2 + 2 + 2 + 2 + keyShare.Length); // key_share
        byte[] body = new byte[bodyLength];
        int index = 0;

        body[index++] = 0x03; body[index++] = 0x03; // legacy_version
        serverRandom.CopyTo(body.AsSpan(index)); index += 32;
        body[index++] = (byte)sessionId.Length;
        sessionId.CopyTo(body.AsSpan(index)); index += sessionId.Length;
        body[index++] = 0x13; body[index++] = 0x01; // cipher suite
        body[index++] = 0x00; // compression

        int extensionsLength = bodyLength - index - 2;
        body[index++] = (byte)(extensionsLength >> 8); body[index++] = (byte)extensionsLength;

        // supported_versions
        body[index++] = 0x00; body[index++] = 0x2B;
        body[index++] = 0x00; body[index++] = 0x02;
        body[index++] = 0x03; body[index++] = 0x04;

        // key_share
        body[index++] = 0x00; body[index++] = 0x33;
        body[index++] = 0x00; body[index++] = (byte)(2 + 2 + keyShare.Length);
        body[index++] = 0x00; body[index++] = 0x1D; // secp256r1
        body[index++] = 0x00; body[index++] = (byte)keyShare.Length;
        keyShare.CopyTo(body.AsSpan(index)); index += keyShare.Length;

        byte[] message = new byte[4 + bodyLength];
        message[0] = (byte)QuicTlsHandshakeMessageType.ServerHello;
        message[1] = (byte)(bodyLength >> 16);
        message[2] = (byte)(bodyLength >> 8);
        message[3] = (byte)bodyLength;
        body.CopyTo(message.AsSpan(4));
        return message;
    }

    private static byte[] CreateServerKeyShare()
    {
        using System.Security.Cryptography.ECDiffieHellman serverKeyPair =
            System.Security.Cryptography.ECDiffieHellman.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        serverKeyPair.ImportParameters(new System.Security.Cryptography.ECParameters
        {
            Curve = System.Security.Cryptography.ECCurve.NamedCurves.nistP256,
            D = CreateScalar(0x02),
        });

        System.Security.Cryptography.ECParameters parameters = serverKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[1 + (2 * 32)];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }
}

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0154")]
public sealed class REQ_QUIC_CRT_0154
{
    private static readonly byte[] HelloRetryRequestRandom = Convert.FromHexString(
        "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedQuicGoFirstClientHelloAcceptsX25519WithoutHelloRetryRequest()
    {
        byte[] capturedClientHello = REQ_QUIC_CRT_0112.CreateCapturedQuicGoServerHandshakeClientHelloTranscript();
        Assert.Contains(
            "0x0033(keyshare=0x11EC:1216/0x001D:32)",
            REQ_QUIC_CRT_0112.DescribeClientHello(capturedClientHello));

        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            capturedClientHello);

        Assert.True(
            updates.Count >= 5,
            $"{REQ_QUIC_CRT_0112.DescribeClientHello(capturedClientHello)} || {DescribeUpdates(updates, driver)}");
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, updates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, updates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, updates[0].TranscriptHashAlgorithm);
        Assert.NotNull(updates[0].TransportParameters);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[1].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Initial, updates[1].EncryptionLevel);
        Assert.Equal(0UL, updates[1].CryptoDataOffset);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, updates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, updates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, updates[4].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[4].EncryptionLevel);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.True(driver.State.TryGetHandshakeOpenPacketProtectionMaterial(out _));
        Assert.True(driver.State.TryGetHandshakeProtectPacketProtectionMaterial(out _));
        Assert.False(driver.State.IsTerminal);

        ServerHelloDescription serverHello = ParseServerHello(updates[1].CryptoData.Span);
        Assert.False(serverHello.Random.AsSpan().SequenceEqual(HelloRetryRequestRandom));
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, serverHello.CipherSuite);
        Assert.Equal(0x0304, serverHello.SupportedVersion);
        Assert.Equal(QuicTlsNamedGroup.X25519, serverHello.SelectedGroup);
        Assert.Equal(32, serverHello.KeyShare.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedNeqoConnectionMigrationClientHelloAcceptsX25519WithoutHelloRetryRequest()
    {
        byte[] capturedClientHello = REQ_QUIC_CRT_0112.CreateCapturedNeqoConnectionMigrationClientHelloTranscript();
        Assert.Contains(
            "0x0033(keyshare=",
            REQ_QUIC_CRT_0112.DescribeClientHello(capturedClientHello));

        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            capturedClientHello);

        Assert.True(
            updates.Count >= 5,
            $"{REQ_QUIC_CRT_0112.DescribeClientHello(capturedClientHello)} || {DescribeUpdates(updates, driver)}");
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, updates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, updates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, updates[0].TranscriptHashAlgorithm);
        Assert.NotNull(updates[0].TransportParameters);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[1].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Initial, updates[1].EncryptionLevel);
        Assert.Equal(0UL, updates[1].CryptoDataOffset);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, updates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, updates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, updates[4].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[4].EncryptionLevel);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.True(driver.State.TryGetHandshakeOpenPacketProtectionMaterial(out _));
        Assert.True(driver.State.TryGetHandshakeProtectPacketProtectionMaterial(out _));
        Assert.False(driver.State.IsTerminal);

        ServerHelloDescription serverHello = ParseServerHello(updates[1].CryptoData.Span);
        Assert.False(serverHello.Random.AsSpan().SequenceEqual(HelloRetryRequestRandom));
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, serverHello.CipherSuite);
        Assert.Equal(0x0304, serverHello.SupportedVersion);
        Assert.Equal(QuicTlsNamedGroup.X25519, serverHello.SelectedGroup);
        Assert.Equal(32, serverHello.KeyShare.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ManagedX25519MatchesRfc7748DiffieHellmanTestVector()
    {
        byte[] alicePrivateKey = Convert.FromHexString(
            "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A");
        byte[] expectedAlicePublicKey = Convert.FromHexString(
            "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A");
        byte[] bobPrivateKey = Convert.FromHexString(
            "5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB");
        byte[] expectedBobPublicKey = Convert.FromHexString(
            "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F");
        byte[] expectedSharedSecret = Convert.FromHexString(
            "4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742");

        byte[] alicePublicKey = new byte[QuicTlsX25519.KeyLength];
        byte[] bobPublicKey = new byte[QuicTlsX25519.KeyLength];
        byte[] aliceSharedSecret = new byte[QuicTlsX25519.KeyLength];
        byte[] bobSharedSecret = new byte[QuicTlsX25519.KeyLength];

        Assert.True(QuicTlsX25519.TryGetPublicKey(alicePrivateKey, alicePublicKey));
        Assert.True(QuicTlsX25519.TryGetPublicKey(bobPrivateKey, bobPublicKey));
        Assert.True(QuicTlsX25519.TryDeriveSharedSecret(alicePrivateKey, bobPublicKey, aliceSharedSecret));
        Assert.True(QuicTlsX25519.TryDeriveSharedSecret(bobPrivateKey, alicePublicKey, bobSharedSecret));

        Assert.Equal(expectedAlicePublicKey, alicePublicKey);
        Assert.Equal(expectedBobPublicKey, bobPublicKey);
        Assert.Equal(expectedSharedSecret, aliceSharedSecret);
        Assert.Equal(expectedSharedSecret, bobSharedSecret);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedX25519ClientHelloKeyShareFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        byte[] clientHello = REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
            supportedGroups: [(ushort)QuicTlsNamedGroup.X25519],
            keyShareNamedGroup: (ushort)QuicTlsNamedGroup.X25519,
            keyShare: REQ_QUIC_CRT_0112.CreateSequentialBytes(0x33, 31));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            clientHello);

        AssertFatalAlert32(updates, driver);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnadvertisedX25519ClientHelloKeyShareFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        byte[] clientHello = REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
            supportedGroups: [(ushort)QuicTlsNamedGroup.Secp256r1],
            keyShareNamedGroup: (ushort)QuicTlsNamedGroup.X25519,
            keyShare: CreateX25519ClientKeyShare(0x31));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            clientHello);

        AssertFatalAlert32(updates, driver);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DuplicateX25519ClientHelloKeySharesFailDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        byte[] clientHello = CreateClientHelloTranscriptWithKeyShareEntries(
            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
            supportedGroups: [(ushort)QuicTlsNamedGroup.X25519],
            keyShareEntries:
            [
                new ClientHelloKeyShareEntry(
                    (ushort)QuicTlsNamedGroup.X25519,
                    CreateX25519ClientKeyShare(0x31)),
                new ClientHelloKeyShareEntry(
                    (ushort)QuicTlsNamedGroup.X25519,
                    CreateX25519ClientKeyShare(0x32)),
            ]);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            clientHello);

        AssertFatalAlert32(updates, driver);
    }

    private static QuicTlsTransportBridgeDriver CreateStartedServerDriver()
    {
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: REQ_QUIC_CRT_0112.CreateScalar(0x22));
        _ = driver.StartHandshake(REQ_QUIC_CRT_0112.CreateBootstrapLocalTransportParameters());
        return driver;
    }

    private static byte[] CreateX25519ClientKeyShare(byte scalarTail)
    {
        byte[] privateKey = REQ_QUIC_CRT_0112.CreateSequentialBytes(0x31, QuicTlsX25519.KeyLength);
        privateKey[^1] = scalarTail;
        byte[] publicKey = new byte[QuicTlsX25519.KeyLength];
        Assert.True(QuicTlsX25519.TryGetPublicKey(privateKey, publicKey));
        return publicKey;
    }

    private static byte[] CreateClientHelloTranscriptWithKeyShareEntries(
        QuicTransportParameters transportParameters,
        IReadOnlyList<ushort> supportedGroups,
        IReadOnlyList<ClientHelloKeyShareEntry> keyShareEntries)
    {
        byte[] supportedVersionsExtension = CreateClientSupportedVersionsExtension();
        byte[] supportedGroupsExtension = CreateClientSupportedGroupsExtension(supportedGroups);
        byte[] keyShareExtension = CreateClientKeyShareExtension(keyShareEntries);
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Client);

        int extensionsLength = supportedVersionsExtension.Length
            + supportedGroupsExtension.Length
            + keyShareExtension.Length
            + transportParametersExtension.Length;
        byte[] body = new byte[43 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;
        REQ_QUIC_CRT_0112.CreateSequentialBytes(0x10, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;
        body[index++] = 0;

        WriteUInt16(body.AsSpan(index, 2), 2);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256);
        index += 2;

        body[index++] = 1;
        body[index++] = 0x00;
        WriteUInt16(body.AsSpan(index, 2), checked((ushort)extensionsLength));
        index += 2;

        supportedVersionsExtension.CopyTo(body.AsSpan(index));
        index += supportedVersionsExtension.Length;
        supportedGroupsExtension.CopyTo(body.AsSpan(index));
        index += supportedGroupsExtension.Length;
        keyShareExtension.CopyTo(body.AsSpan(index));
        index += keyShareExtension.Length;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] CreateClientSupportedVersionsExtension()
    {
        byte[] extension = new byte[2 + 2 + 1 + 2];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x002B);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), 3);
        index += 2;
        extension[index++] = 2;
        WriteUInt16(extension.AsSpan(index, 2), 0x0304);
        return extension;
    }

    private static byte[] CreateClientSupportedGroupsExtension(IReadOnlyList<ushort> supportedGroups)
    {
        byte[] extension = new byte[2 + 2 + 2 + (supportedGroups.Count * 2)];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x000A);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + (supportedGroups.Count * 2))));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(supportedGroups.Count * 2)));
        index += 2;
        foreach (ushort supportedGroup in supportedGroups)
        {
            WriteUInt16(extension.AsSpan(index, 2), supportedGroup);
            index += 2;
        }

        return extension;
    }

    private static byte[] CreateClientKeyShareExtension(IReadOnlyList<ClientHelloKeyShareEntry> keyShareEntries)
    {
        int keyShareVectorLength = 0;
        foreach (ClientHelloKeyShareEntry keyShareEntry in keyShareEntries)
        {
            keyShareVectorLength += 2 + 2 + keyShareEntry.KeyExchange.Length;
        }

        byte[] extension = new byte[2 + 2 + 2 + keyShareVectorLength];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x0033);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + keyShareVectorLength)));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)keyShareVectorLength));
        index += 2;

        foreach (ClientHelloKeyShareEntry keyShareEntry in keyShareEntries)
        {
            WriteUInt16(extension.AsSpan(index, 2), keyShareEntry.NamedGroup);
            index += 2;
            WriteUInt16(extension.AsSpan(index, 2), checked((ushort)keyShareEntry.KeyExchange.Length));
            index += 2;
            keyShareEntry.KeyExchange.CopyTo(extension.AsSpan(index));
            index += keyShareEntry.KeyExchange.Length;
        }

        return extension;
    }

    private static byte[] CreateTransportParametersExtension(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole role)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            role,
            encodedTransportParameters,
            out int bytesWritten));

        byte[] extension = new byte[4 + bytesWritten];
        WriteUInt16(extension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        WriteUInt16(extension.AsSpan(2, 2), (ushort)bytesWritten);
        encodedTransportParameters.AsSpan(0, bytesWritten).CopyTo(extension.AsSpan(4));
        return extension;
    }

    private static ServerHelloDescription ParseServerHello(ReadOnlySpan<byte> serverHelloBytes)
    {
        Assert.True(serverHelloBytes.Length >= 4);
        Assert.Equal((byte)QuicTlsHandshakeMessageType.ServerHello, serverHelloBytes[0]);

        int index = 4;
        Assert.Equal(0x0303, ReadUInt16(serverHelloBytes, ref index));

        byte[] random = serverHelloBytes.Slice(index, 32).ToArray();
        index += 32;

        int sessionIdLength = serverHelloBytes[index++];
        index += sessionIdLength;

        QuicTlsCipherSuite cipherSuite = (QuicTlsCipherSuite)ReadUInt16(serverHelloBytes, ref index);
        Assert.Equal(0x00, serverHelloBytes[index++]);

        int extensionsLength = ReadUInt16(serverHelloBytes, ref index);
        int extensionsEnd = index + extensionsLength;
        ushort supportedVersion = 0;
        QuicTlsNamedGroup selectedGroup = 0;
        byte[] keyShare = [];
        bool foundSupportedVersion = false;
        bool foundKeyShare = false;

        while (index < extensionsEnd)
        {
            ushort extensionType = ReadUInt16(serverHelloBytes, ref index);
            int extensionLength = ReadUInt16(serverHelloBytes, ref index);
            ReadOnlySpan<byte> extensionValue = serverHelloBytes.Slice(index, extensionLength);
            index += extensionLength;

            switch (extensionType)
            {
                case 0x002B:
                    Assert.False(foundSupportedVersion);
                    Assert.Equal(sizeof(ushort), extensionLength);
                    int supportedVersionIndex = 0;
                    supportedVersion = ReadUInt16(extensionValue, ref supportedVersionIndex);
                    Assert.Equal(extensionLength, supportedVersionIndex);
                    foundSupportedVersion = true;
                    break;

                case 0x0033:
                    Assert.False(foundKeyShare);
                    int keyShareIndex = 0;
                    selectedGroup = (QuicTlsNamedGroup)ReadUInt16(extensionValue, ref keyShareIndex);
                    int keyShareLength = ReadUInt16(extensionValue, ref keyShareIndex);
                    keyShare = extensionValue.Slice(keyShareIndex, keyShareLength).ToArray();
                    keyShareIndex += keyShareLength;
                    Assert.Equal(extensionLength, keyShareIndex);
                    foundKeyShare = true;
                    break;

                default:
                    Assert.Fail($"Unexpected ServerHello extension 0x{extensionType:X4}.");
                    break;
            }
        }

        Assert.Equal(extensionsEnd, index);
        Assert.True(foundSupportedVersion);
        Assert.True(foundKeyShare);
        return new ServerHelloDescription(random, cipherSuite, supportedVersion, selectedGroup, keyShare);
    }

    private static void AssertFatalAlert32(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        QuicTlsTransportBridgeDriver driver)
    {
        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.HandshakeKeysAvailable);
    }

    private static string DescribeUpdates(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        QuicTlsTransportBridgeDriver driver)
    {
        return string.Join(
            " | ",
            [
                $"count={updates.Count}",
                $"kinds={string.Join(",", updates.Select(update => update.Kind))}",
                $"alerts={string.Join(",", updates.Where(update => update.AlertDescription.HasValue).Select(update => $"0x{update.AlertDescription!.Value:X4}"))}",
                $"terminal={driver.State.IsTerminal}",
                $"phase={driver.State.HandshakeTranscriptPhase}",
                $"message={driver.State.HandshakeMessageType?.ToString() ?? "<null>"}",
                $"selectedCipher={driver.State.SelectedCipherSuite?.ToString() ?? "<null>"}",
                $"hash={driver.State.TranscriptHashAlgorithm?.ToString() ?? "<null>"}",
            ]);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> source, ref int index)
    {
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(index, 2));
        index += 2;
        return value;
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

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, 3), body.Length);
        body.CopyTo(transcript.AsSpan(4));
        return transcript;
    }

    private readonly record struct ClientHelloKeyShareEntry(
        ushort NamedGroup,
        byte[] KeyExchange);

    private readonly record struct ServerHelloDescription(
        byte[] Random,
        QuicTlsCipherSuite CipherSuite,
        ushort SupportedVersion,
        QuicTlsNamedGroup SelectedGroup,
        byte[] KeyShare);
}

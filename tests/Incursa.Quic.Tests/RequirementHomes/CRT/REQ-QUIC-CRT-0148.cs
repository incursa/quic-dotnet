using System.Buffers.Binary;
using System.Net.Security;
using System.Text;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0148")]
public sealed class REQ_QUIC_CRT_0148
{
    private static readonly byte[] Http3Protocol = SslApplicationProtocol.Http3.Protocol.ToArray();
    private static readonly byte[] CustomInteropProtocol = Encoding.ASCII.GetBytes("incursa-interop");
    private static readonly byte[] UnsupportedProtocol = Encoding.ASCII.GetBytes("hq-29");

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleSelectsTheFirstMutualConfiguredApplicationProtocolByLocalOrderAndEmitsItInEncryptedExtensions()
    {
        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver(
            [new SslApplicationProtocol(CustomInteropProtocol), SslApplicationProtocol.Http3]);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                applicationProtocols:
                [
                    Http3Protocol,
                    CustomInteropProtocol,
                ]));

        Assert.True(updates.Count >= 6);
        Assert.True(driver.State.HandshakeKeysAvailable);

        EncryptedExtensionsDescription encryptedExtensions = ParseEncryptedExtensions(updates[5].CryptoData.ToArray());
        Assert.True(encryptedExtensions.TransportParametersPresent);
        Assert.Equal(1, encryptedExtensions.ApplicationProtocolExtensionCount);
        Assert.Equal("incursa-interop", Encoding.ASCII.GetString(encryptedExtensions.SelectedApplicationProtocol));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleFailsWithNoApplicationProtocolWhenPeerOmitsAlpnBeforeServerHelloOrHandshakeKeys()
    {
        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver([SslApplicationProtocol.Http3]);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            REQ_QUIC_CRT_0112.CreateClientHelloTranscript(CreateClientTransportParameters()));

        AssertNoApplicationProtocolFailure(updates, driver);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleFailsWithNoApplicationProtocolWhenPeerOffersOnlyUnsupportedProtocols()
    {
        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver([SslApplicationProtocol.Http3]);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                applicationProtocols:
                [
                    UnsupportedProtocol,
                ]));

        AssertNoApplicationProtocolFailure(updates, driver);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicGoHelloRetryRequestFollowOnReplayPublishesExactlyOneSelectedHttp3ProtocolInsideEncryptedExtensions()
    {
        // Provenance: preserved server-role handshake rerun narrowed to the post-HRR
        // `server did not select an ALPN protocol` failure under
        // artifacts/interop-runner/20260422-125529196-server-nginx/
        // runner-logs/nginx_quic-go/handshake/output.txt,
        // runner-logs/nginx_quic-go/handshake/client/log.txt, and
        // runner-logs/nginx_quic-go/handshake/server/qlog/server-handshake-4cd8218da0654fa3b7534582e451a0c8.qlog.
        byte[] retryEligibleClientHello = REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
            CreateClientTransportParameters(),
            supportedGroups: [(ushort)QuicTlsNamedGroup.Secp256r1, 0x001D],
            applicationProtocols:
            [
                Http3Protocol,
            ],
            keyShareNamedGroup: 0x001D,
            keyShare: REQ_QUIC_CRT_0112.CreateSequentialBytes(0x90, 32));
        byte[] retriedClientHello = REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
            CreateClientTransportParameters(),
            applicationProtocols:
            [
                Http3Protocol,
            ]);

        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver([SslApplicationProtocol.Http3]);
        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retryEligibleClientHello);

        Assert.Equal(2, firstUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, firstUpdates[1].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Initial, firstUpdates[1].EncryptionLevel);

        byte[] helloRetryRequest = new byte[firstUpdates[1].CryptoData.Length];
        Assert.True(driver.TryDequeueOutgoingCryptoData(
            QuicTlsEncryptionLevel.Initial,
            helloRetryRequest,
            out ulong helloRetryRequestOffset,
            out int helloRetryRequestBytesWritten));
        Assert.Equal(0UL, helloRetryRequestOffset);
        Assert.Equal(helloRetryRequest.Length, helloRetryRequestBytesWritten);

        IReadOnlyList<QuicTlsStateUpdate> secondUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retriedClientHello);

        Assert.True(secondUpdates.Count >= 6);
        Assert.Equal((ulong)helloRetryRequest.Length, secondUpdates[1].CryptoDataOffset);
        Assert.True(driver.State.HandshakeKeysAvailable);

        EncryptedExtensionsDescription encryptedExtensions = ParseEncryptedExtensions(secondUpdates[5].CryptoData.ToArray());
        Assert.True(encryptedExtensions.TransportParametersPresent);
        Assert.Equal(1, encryptedExtensions.ApplicationProtocolExtensionCount);
        Assert.Equal("h3", Encoding.ASCII.GetString(encryptedExtensions.SelectedApplicationProtocol));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzApplicationProtocolOfferBoundary_PermutedOffersDuplicatesAndMalformedLengthsStayWithinTheSelectedProtocolOrNoApplicationProtocolSlice()
    {
        Random random = new(0x0148);

        for (int iteration = 0; iteration < 48; iteration++)
        {
            QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver(
                [new SslApplicationProtocol(CustomInteropProtocol), SslApplicationProtocol.Http3]);

            int scenario = iteration % 4;
            IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
                QuicTlsEncryptionLevel.Initial,
                scenario switch
                {
                    0 => REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
                        CreateClientTransportParameters(),
                        applicationProtocols: Shuffle(
                            random,
                            [
                                Http3Protocol,
                                CustomInteropProtocol,
                                Encoding.ASCII.GetBytes($"interop-{iteration:X2}"),
                            ])),
                    1 => REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
                        CreateClientTransportParameters(),
                        applicationProtocols:
                        [
                            Encoding.ASCII.GetBytes($"unsupported-{iteration:X2}"),
                            UnsupportedProtocol,
                        ]),
                    2 => REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
                        CreateClientTransportParameters(),
                        applicationProtocols:
                        [
                            Http3Protocol,
                            Http3Protocol,
                        ]),
                    _ => CorruptApplicationProtocolListLength(
                        REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
                            CreateClientTransportParameters(),
                            applicationProtocols:
                            [
                                Http3Protocol,
                                CustomInteropProtocol,
                            ])),
                });

            switch (scenario)
            {
                case 0:
                {
                    Assert.True(updates.Count >= 6);
                    Assert.True(driver.State.HandshakeKeysAvailable);
                    EncryptedExtensionsDescription encryptedExtensions = ParseEncryptedExtensions(updates[5].CryptoData.ToArray());
                    Assert.True(encryptedExtensions.TransportParametersPresent);
                    Assert.Equal("incursa-interop", Encoding.ASCII.GetString(encryptedExtensions.SelectedApplicationProtocol));
                    break;
                }

                case 1:
                case 2:
                case 3:
                    AssertNoApplicationProtocolFailure(updates, driver);
                    break;
            }
        }
    }

    private static QuicTlsTransportBridgeDriver CreateStartedServerDriver(IReadOnlyList<SslApplicationProtocol> applicationProtocols)
    {
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: REQ_QUIC_CRT_0112.CreateScalar(0x22));
        Assert.True(driver.TryConfigureLocalApplicationProtocols(applicationProtocols));
        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(CreateServerTransportParameters());
        Assert.Single(bootstrapUpdates);
        Assert.Equal(QuicTlsUpdateKind.LocalTransportParametersReady, bootstrapUpdates[0].Kind);
        return driver;
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

    private static void AssertNoApplicationProtocolFailure(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        QuicTlsTransportBridgeDriver driver)
    {
        int fatalAlertCount = 0;
        ushort fatalAlertDescription = 0;
        foreach (QuicTlsStateUpdate update in updates)
        {
            Assert.NotEqual(QuicTlsUpdateKind.CryptoDataAvailable, update.Kind);
            Assert.NotEqual(QuicTlsUpdateKind.KeysAvailable, update.Kind);

            if (update.Kind == QuicTlsUpdateKind.FatalAlert)
            {
                fatalAlertCount++;
                Assert.True(update.AlertDescription.HasValue);
                fatalAlertDescription = update.AlertDescription.Value;
            }
        }

        Assert.Equal(1, fatalAlertCount);
        Assert.Equal((ushort)0x0078, fatalAlertDescription);
        Assert.False(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Initial,
            stackalloc byte[1],
            out _,
            out _));
        Assert.False(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            stackalloc byte[1],
            out _,
            out _));
    }

    private static EncryptedExtensionsDescription ParseEncryptedExtensions(byte[] encryptedExtensions)
    {
        Assert.True(encryptedExtensions.Length >= 6);
        Assert.Equal((byte)QuicTlsHandshakeMessageType.EncryptedExtensions, encryptedExtensions[0]);

        int declaredBodyLength = ReadUInt24(encryptedExtensions.AsSpan(1, 3));
        Assert.Equal(encryptedExtensions.Length - 4, declaredBodyLength);

        ReadOnlySpan<byte> body = encryptedExtensions.AsSpan(4);
        int index = 0;
        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(index, 2));
        index += 2;
        Assert.Equal(body.Length - 2, extensionsLength);

        bool transportParametersPresent = false;
        int applicationProtocolExtensionCount = 0;
        byte[] selectedApplicationProtocol = [];
        while (index < body.Length)
        {
            ushort extensionType = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(index, 2));
            index += 2;
            ushort extensionLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(index, 2));
            index += 2;
            ReadOnlySpan<byte> extensionValue = body.Slice(index, extensionLength);
            index += extensionLength;

            if (extensionType == QuicTransportParametersCodec.QuicTransportParametersExtensionType)
            {
                transportParametersPresent = true;
                continue;
            }

            if (extensionType == 0x0010)
            {
                applicationProtocolExtensionCount++;
                selectedApplicationProtocol = ParseSelectedApplicationProtocol(extensionValue);
            }
        }

        Assert.Equal(body.Length, index);
        return new EncryptedExtensionsDescription(
            transportParametersPresent,
            applicationProtocolExtensionCount,
            selectedApplicationProtocol);
    }

    private static byte[] ParseSelectedApplicationProtocol(ReadOnlySpan<byte> extensionValue)
    {
        int index = 0;
        ushort protocolListLength = BinaryPrimitives.ReadUInt16BigEndian(extensionValue.Slice(index, 2));
        index += 2;
        Assert.Equal(extensionValue.Length - 2, protocolListLength);

        int protocolNameLength = extensionValue[index++];
        byte[] selectedProtocol = extensionValue.Slice(index, protocolNameLength).ToArray();
        index += protocolNameLength;

        Assert.Equal(extensionValue.Length, index);
        return selectedProtocol;
    }

    private static byte[] CorruptApplicationProtocolListLength(byte[] clientHello)
    {
        byte[] malformedClientHello = clientHello.ToArray();
        Assert.True(TryLocateApplicationProtocolExtension(malformedClientHello, out int extensionValueOffset, out _));
        ushort protocolListLength = BinaryPrimitives.ReadUInt16BigEndian(
            malformedClientHello.AsSpan(extensionValueOffset, 2));
        BinaryPrimitives.WriteUInt16BigEndian(
            malformedClientHello.AsSpan(extensionValueOffset, 2),
            checked((ushort)(protocolListLength + 1)));
        return malformedClientHello;
    }

    private static bool TryLocateApplicationProtocolExtension(
        byte[] clientHello,
        out int extensionValueOffset,
        out int extensionValueLength)
    {
        extensionValueOffset = 0;
        extensionValueLength = 0;

        if (clientHello.Length <= 47 || clientHello[0] != (byte)QuicTlsHandshakeMessageType.ClientHello)
        {
            return false;
        }

        int index = 4;
        index += 2 + 32;

        int sessionIdLength = clientHello[index++];
        index += sessionIdLength;

        ushort cipherSuitesLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(index, 2));
        index += 2 + cipherSuitesLength;

        int compressionMethodsLength = clientHello[index++];
        index += compressionMethodsLength;

        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(index, 2));
        index += 2;

        int extensionsEnd = index + extensionsLength;
        while (index < extensionsEnd)
        {
            ushort extensionType = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(index, 2));
            index += 2;
            ushort currentExtensionLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(index, 2));
            index += 2;
            if (extensionType == 0x0010)
            {
                extensionValueOffset = index;
                extensionValueLength = currentExtensionLength;
                return true;
            }

            index += currentExtensionLength;
        }

        return false;
    }

    private static int ReadUInt24(ReadOnlySpan<byte> bytes)
    {
        return (bytes[0] << 16)
            | (bytes[1] << 8)
            | bytes[2];
    }

    private static T[] Shuffle<T>(Random random, IReadOnlyList<T> source)
    {
        T[] shuffled = new T[source.Count];
        for (int index = 0; index < source.Count; index++)
        {
            shuffled[index] = source[index];
        }

        for (int index = shuffled.Length - 1; index > 0; index--)
        {
            int swapIndex = random.Next(index + 1);
            (shuffled[index], shuffled[swapIndex]) = (shuffled[swapIndex], shuffled[index]);
        }

        return shuffled;
    }

    private sealed record EncryptedExtensionsDescription(
        bool TransportParametersPresent,
        int ApplicationProtocolExtensionCount,
        byte[] SelectedApplicationProtocol);
}

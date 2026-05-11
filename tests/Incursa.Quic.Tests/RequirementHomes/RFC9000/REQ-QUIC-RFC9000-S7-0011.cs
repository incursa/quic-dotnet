using System.Buffers.Binary;
using System.Net.Security;
using System.Text;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7-0011")]
public sealed class REQ_QUIC_RFC9000_S7_0011
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
            [new SslApplicationProtocol("incursa-interop"), SslApplicationProtocol.Http3]);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                applicationProtocols:
                [
                    Http3Protocol,
                    CustomInteropProtocol,
                ]));

        AssertSelectedApplicationProtocol(updates, CustomInteropProtocol);
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
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzApplicationProtocolOfferBoundary_PermutedOffersStayWithinTheSelectedProtocolSlice()
    {
        byte[][][] applicationProtocolOffers =
        [
            [Http3Protocol, CustomInteropProtocol],
            [CustomInteropProtocol, Http3Protocol],
            [UnsupportedProtocol, CustomInteropProtocol, Http3Protocol],
            [Http3Protocol, UnsupportedProtocol],
            [UnsupportedProtocol, Http3Protocol],
        ];

        byte[][] expectedSelectedProtocols =
        [
            CustomInteropProtocol,
            CustomInteropProtocol,
            CustomInteropProtocol,
            Http3Protocol,
            Http3Protocol,
        ];

        for (int index = 0; index < applicationProtocolOffers.Length; index++)
        {
            QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver(
                [new SslApplicationProtocol("incursa-interop"), SslApplicationProtocol.Http3]);

            IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
                QuicTlsEncryptionLevel.Initial,
                REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
                    CreateClientTransportParameters(),
                    applicationProtocols: applicationProtocolOffers[index]));

            AssertSelectedApplicationProtocol(updates, expectedSelectedProtocols[index]);
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

    private static void AssertSelectedApplicationProtocol(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        ReadOnlySpan<byte> expectedProtocol)
    {
        Assert.True(updates.Count >= 6);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[5].Kind);
        Assert.True(updates[5].CryptoData.Length > 0);

        EncryptedExtensionsDescription encryptedExtensions = ParseEncryptedExtensions(updates[5].CryptoData.ToArray());
        Assert.True(encryptedExtensions.TransportParametersPresent);
        Assert.Equal(1, encryptedExtensions.ApplicationProtocolExtensionCount);
        Assert.True(encryptedExtensions.SelectedApplicationProtocol.AsSpan().SequenceEqual(expectedProtocol));
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

    private static int ReadUInt24(ReadOnlySpan<byte> bytes)
    {
        return (bytes[0] << 16)
            | (bytes[1] << 8)
            | bytes[2];
    }

    private sealed record EncryptedExtensionsDescription(
        bool TransportParametersPresent,
        int ApplicationProtocolExtensionCount,
        byte[] SelectedApplicationProtocol);
}

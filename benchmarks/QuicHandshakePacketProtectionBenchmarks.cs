using BenchmarkDotNet.Attributes;
using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Cryptography;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the Handshake packet protection helper.
/// </summary>
[MemoryDiagnoser]
public class QuicHandshakePacketProtectionBenchmarks
{
    private static readonly byte[] DestinationConnectionId =
    [
        0x10, 0x11, 0x12, 0x13,
    ];

    private static readonly byte[] SourceConnectionId =
    [
        0x20, 0x21,
    ];

    private QuicHandshakePacketProtection senderProtection = default!;
    private QuicHandshakePacketProtection receiverProtection = default!;
    private QuicTlsPacketProtectionMaterial handshakePacketMaterial;
    private QuicInitialPacketProtection initialPacketProtection = default!;
    private QuicHandshakeFlowCoordinator initialPacketBuilder = default!;
    private QuicHandshakeFlowCoordinator initialAckPacketBuilder = default!;
    private QuicHandshakeFlowCoordinator initialRetransmissionAckPacketBuilder = default!;
    private QuicHandshakeFlowCoordinator handshakePacketBuilder = default!;
    private QuicHandshakeFlowCoordinator handshakeAckPacketBuilder = default!;
    private QuicHandshakeFlowCoordinator handshakeRetransmissionAckPacketBuilder = default!;
    private byte[] plaintextPacket = [];
    private byte[] protectedPacket = [];
    private byte[] recoveredPacket = [];
    private byte[] cryptoPayload = [];
    private byte[] ackFramePayload = [];

    /// <summary>
    /// Prepares representative Handshake packet inputs and reusable buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        byte[] aeadKey = CreateSequentialBytes(0x11, 32);
        byte[] aeadIv = CreateSequentialBytes(0x21, 12);
        byte[] headerProtectionKey = CreateSequentialBytes(0x31, 32);

        if (!QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes256Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material))
        {
            throw new InvalidOperationException("Failed to create representative Handshake packet protection material.");
        }

        handshakePacketMaterial = material;
        if (!QuicHandshakePacketProtection.TryCreate(material, out senderProtection))
        {
            throw new InvalidOperationException("Failed to create a representative Handshake sender protector.");
        }

        if (!QuicHandshakePacketProtection.TryCreate(material, out receiverProtection))
        {
            throw new InvalidOperationException("Failed to create a representative Handshake receiver protector.");
        }

        plaintextPacket = BuildHandshakePlaintextPacket(
            DestinationConnectionId,
            SourceConnectionId,
            packetNumber: [0x01, 0x02],
            plaintextPayload:
            [
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
                0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
                0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
                0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
            ]);

        protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        recoveredPacket = new byte[plaintextPacket.Length];

        if (!senderProtection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten)
            || bytesWritten != protectedPacket.Length)
        {
            throw new InvalidOperationException("Failed to produce a representative protected Handshake packet.");
        }

        if (!QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            DestinationConnectionId,
            out initialPacketProtection))
        {
            throw new InvalidOperationException("Failed to create representative Initial packet protection.");
        }

        cryptoPayload = CreateSequentialBytes(0x41, 96);
        ackFramePayload = BuildAckFramePayload(largestAcknowledged: 23);
        initialPacketBuilder = new QuicHandshakeFlowCoordinator(DestinationConnectionId, SourceConnectionId);
        initialAckPacketBuilder = new QuicHandshakeFlowCoordinator(DestinationConnectionId, SourceConnectionId);
        initialRetransmissionAckPacketBuilder = new QuicHandshakeFlowCoordinator(DestinationConnectionId, SourceConnectionId);
        handshakePacketBuilder = new QuicHandshakeFlowCoordinator(DestinationConnectionId, SourceConnectionId);
        handshakeAckPacketBuilder = new QuicHandshakeFlowCoordinator(DestinationConnectionId, SourceConnectionId);
        handshakeRetransmissionAckPacketBuilder = new QuicHandshakeFlowCoordinator(DestinationConnectionId, SourceConnectionId);
    }

    /// <summary>
    /// Measures Handshake packet protection.
    /// </summary>
    [Benchmark]
    public int ProtectHandshakePacket()
    {
        return senderProtection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Handshake packet opening.
    /// </summary>
    [Benchmark]
    public int OpenHandshakePacket()
    {
        return receiverProtection.TryOpen(protectedPacket, recoveredPacket, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures protected Initial CRYPTO packet construction without an ACK prefix.
    /// </summary>
    [Benchmark]
    public int BuildInitialCryptoPacket()
    {
        return initialPacketBuilder.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            initialPacketProtection,
            out byte[] packet)
            ? packet.Length
            : -1;
    }

    /// <summary>
    /// Measures protected Initial CRYPTO packet construction with an ACK prefix.
    /// </summary>
    [Benchmark]
    public int BuildInitialCryptoPacketWithAck()
    {
        return initialAckPacketBuilder.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            ackFramePayload,
            initialPacketProtection,
            out byte[] packet)
            ? packet.Length
            : -1;
    }

    /// <summary>
    /// Measures rebuilt protected Initial CRYPTO retransmission construction with a fresh ACK prefix.
    /// </summary>
    [Benchmark]
    public int BuildInitialCryptoRetransmissionPacketWithAck()
    {
        return initialRetransmissionAckPacketBuilder.TryBuildProtectedInitialPacketForRetransmission(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            initialDestinationConnectionId: DestinationConnectionId,
            destinationConnectionId: DestinationConnectionId,
            sourceConnectionId: SourceConnectionId,
            token: ReadOnlySpan<byte>.Empty,
            prefixFramePayload: ackFramePayload,
            protection: initialPacketProtection,
            out _,
            out byte[] packet)
            ? packet.Length
            : -1;
    }

    /// <summary>
    /// Measures protected Handshake CRYPTO packet construction without an ACK prefix.
    /// </summary>
    [Benchmark]
    public int BuildHandshakeCryptoPacket()
    {
        return handshakePacketBuilder.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            handshakePacketMaterial,
            out byte[] packet)
            ? packet.Length
            : -1;
    }

    /// <summary>
    /// Measures protected Handshake CRYPTO packet construction with an ACK prefix.
    /// </summary>
    [Benchmark]
    public int BuildHandshakeCryptoPacketWithAck()
    {
        return handshakeAckPacketBuilder.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            ackFramePayload,
            handshakePacketMaterial,
            out byte[] packet)
            ? packet.Length
            : -1;
    }

    /// <summary>
    /// Measures rebuilt protected Handshake CRYPTO retransmission construction with a fresh ACK prefix.
    /// </summary>
    [Benchmark]
    public int BuildHandshakeCryptoRetransmissionPacketWithAck()
    {
        return handshakeRetransmissionAckPacketBuilder.TryBuildProtectedHandshakePacketForRetransmission(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            destinationConnectionId: DestinationConnectionId,
            sourceConnectionId: SourceConnectionId,
            prefixFramePayload: ackFramePayload,
            material: handshakePacketMaterial,
            out _,
            out byte[] packet)
            ? packet.Length
            : -1;
    }

    private static byte[] BuildHandshakePlaintextPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] versionSpecificData = BuildHandshakeVersionSpecificData(packetNumber, plaintextPayload);
        return BuildLongHeader(
            headerControlBits: (byte)(0x60 | ((packetNumber.Length - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask)),
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);
    }

    private static byte[] BuildHandshakeVersionSpecificData(
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] lengthBytes = EncodeVarint((ulong)(packetNumber.Length + plaintextPayload.Length + QuicInitialPacketProtection.AuthenticationTagLength));
        byte[] versionSpecificData = new byte[lengthBytes.Length + packetNumber.Length + plaintextPayload.Length];

        int offset = 0;
        lengthBytes.CopyTo(versionSpecificData, offset);
        offset += lengthBytes.Length;
        packetNumber.CopyTo(versionSpecificData.AsSpan(offset));
        offset += packetNumber.Length;
        plaintextPayload.CopyTo(versionSpecificData.AsSpan(offset));

        return versionSpecificData;
    }

    private static byte[] BuildLongHeader(
        byte headerControlBits,
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> versionSpecificData)
    {
        byte[] packet = new byte[1 + sizeof(uint) + 1 + destinationConnectionId.Length + 1 + sourceConnectionId.Length + versionSpecificData.Length];
        packet[0] = (byte)(0x80 | (headerControlBits & 0x7F));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, sizeof(uint)), version);
        packet[5] = (byte)destinationConnectionId.Length;

        int sourceConnectionIdLengthOffset = 6 + destinationConnectionId.Length;
        destinationConnectionId.CopyTo(packet.AsSpan(6));
        packet[sourceConnectionIdLengthOffset] = (byte)sourceConnectionId.Length;

        int versionSpecificDataOffset = sourceConnectionIdLengthOffset + 1 + sourceConnectionId.Length;
        sourceConnectionId.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1));
        versionSpecificData.CopyTo(packet.AsSpan(versionSpecificDataOffset));

        return packet;
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        if (!QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to encode a representative QUIC varint.");
        }

        return buffer[..bytesWritten].ToArray();
    }

    private static byte[] BuildAckFramePayload(ulong largestAcknowledged)
    {
        byte[] destination = new byte[32];
        if (!QuicFrameCodec.TryFormatAckFrame(
            new QuicAckFrame
            {
                FrameType = 0x02,
                LargestAcknowledged = largestAcknowledged,
                AckDelay = 0,
                FirstAckRange = 0,
            },
            destination,
            out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to encode a representative ACK frame.");
        }

        return destination[..bytesWritten];
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
}

/// <summary>
/// Benchmarks the server-role HelloRetryRequest branch and the retried ClientHello handoff back into the existing ServerHello floor.
/// </summary>
[MemoryDiagnoser]
public class QuicTlsServerHelloRetryRequestBenchmarks
{
    private static readonly byte[] Http3Protocol = SslApplicationProtocol.Http3.Protocol.ToArray();

    private byte[] localHandshakePrivateKey = [];
    private QuicTransportParameters localTransportParameters = default!;
    private QuicTransportParameters peerTransportParameters = default!;
    private byte[] retryEligibleClientHello = [];
    private byte[] retriedClientHello = [];
    private QuicTlsTransportBridgeDriver retryEmissionDriver = default!;
    private QuicTlsTransportBridgeDriver retryRejoinDriver = default!;

    /// <summary>
    /// Prepares deterministic server-role transport parameters and representative retry-eligible plus retried ClientHello inputs.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        localHandshakePrivateKey = CreateScalar(0x22);
        localTransportParameters = CreateBootstrapLocalTransportParameters();
        peerTransportParameters = CreateClientTransportParameters();
        retryEligibleClientHello = CreateClientHelloTranscriptWithKeyShareEntries(
            peerTransportParameters,
            supportedGroups: [(ushort)QuicTlsNamedGroup.Secp256r1, (ushort)0x001D, (ushort)0x11EC],
            keyShareEntries:
            [
                new ClientHelloKeyShareEntry(0x001D, CreateSequentialBytes(0x90, 32)),
                new ClientHelloKeyShareEntry(0x11EC, CreateSequentialBytes(0xA0, 48)),
            ],
            applicationProtocols: [Http3Protocol]);
        retriedClientHello = CreateClientHelloTranscriptWithKeyShareEntries(
            peerTransportParameters,
            supportedGroups: [(ushort)QuicTlsNamedGroup.Secp256r1, (ushort)0x001D, (ushort)0x11EC],
            keyShareEntries:
            [
                new ClientHelloKeyShareEntry((ushort)QuicTlsNamedGroup.Secp256r1, CreateValidSecp256r1KeyShare(0x33)),
                new ClientHelloKeyShareEntry(0x001D, CreateSequentialBytes(0xB0, 32)),
            ],
            applicationProtocols: [Http3Protocol]);
    }

    /// <summary>
    /// Rebuilds deterministic server-handshake state for the first retry-eligible ClientHello and for the retried ClientHello handoff.
    /// </summary>
    [IterationSetup]
    public void IterationSetup()
    {
        retryEmissionDriver = CreateStartedServerDriver();
        retryRejoinDriver = CreateStartedServerDriver();

        IReadOnlyList<QuicTlsStateUpdate> retryUpdates = retryRejoinDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retryEligibleClientHello);
        if (retryUpdates.Count != 2 || retryUpdates[1].Kind != QuicTlsUpdateKind.CryptoDataAvailable)
        {
            throw new InvalidOperationException("Failed to prepare the representative HelloRetryRequest boundary.");
        }

        byte[] helloRetryRequest = new byte[retryUpdates[1].CryptoData.Length];
        if (!retryRejoinDriver.TryDequeueOutgoingCryptoData(
            QuicTlsEncryptionLevel.Initial,
            helloRetryRequest,
            out _,
            out int bytesWritten)
            || bytesWritten != helloRetryRequest.Length)
        {
            throw new InvalidOperationException("Failed to dequeue the representative HelloRetryRequest.");
        }
    }

    /// <summary>
    /// Measures the retry-eligible ClientHello branch that emits exactly one deterministic HelloRetryRequest.
    /// </summary>
    [Benchmark]
    public int EmitHelloRetryRequestForRetryEligibleClientHello()
    {
        return retryEmissionDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retryEligibleClientHello).Count;
    }

    /// <summary>
    /// Measures the retried ClientHello branch that rejoins the existing ServerHello and Handshake-key publication floor.
    /// </summary>
    [Benchmark]
    public int RejoinServerHelloFloorAfterRetriedClientHello()
    {
        return retryRejoinDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retriedClientHello).Count;
    }

    private QuicTlsTransportBridgeDriver CreateStartedServerDriver()
    {
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey);
        if (!driver.TryConfigureLocalApplicationProtocols([SslApplicationProtocol.Http3]))
        {
            throw new InvalidOperationException("Failed to configure the representative server ALPN list.");
        }

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(localTransportParameters);
        if (bootstrapUpdates.Count != 1 || bootstrapUpdates[0].Kind != QuicTlsUpdateKind.LocalTransportParametersReady)
        {
            throw new InvalidOperationException("Failed to prepare the representative server handshake bootstrap.");
        }

        return driver;
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

    private static byte[] CreateClientHelloTranscriptWithKeyShareEntries(
        QuicTransportParameters transportParameters,
        IReadOnlyList<ushort> supportedGroups,
        IReadOnlyList<ClientHelloKeyShareEntry> keyShareEntries,
        IReadOnlyList<byte[]>? applicationProtocols = null)
    {
        byte[] supportedVersionsExtension = CreateClientSupportedVersionsExtension();
        byte[]? applicationProtocolsExtension = applicationProtocols is { Count: > 0 }
            ? CreateClientApplicationProtocolNegotiationExtension(applicationProtocols)
            : null;
        byte[] supportedGroupsExtension = CreateClientSupportedGroupsExtension(supportedGroups);
        byte[] keyShareExtension = CreateClientKeyShareExtension(keyShareEntries);
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Client);

        int extensionsLength = supportedVersionsExtension.Length
            + (applicationProtocolsExtension?.Length ?? 0)
            + supportedGroupsExtension.Length
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
        WriteUInt16(body.AsSpan(index, 2), checked((ushort)extensionsLength));
        index += 2;

        supportedVersionsExtension.CopyTo(body.AsSpan(index));
        index += supportedVersionsExtension.Length;
        applicationProtocolsExtension?.CopyTo(body.AsSpan(index));
        index += applicationProtocolsExtension?.Length ?? 0;
        supportedGroupsExtension.CopyTo(body.AsSpan(index));
        index += supportedGroupsExtension.Length;
        keyShareExtension.CopyTo(body.AsSpan(index));
        index += keyShareExtension.Length;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] CreateClientApplicationProtocolNegotiationExtension(IReadOnlyList<byte[]> applicationProtocols)
    {
        int protocolListLength = 0;
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            protocolListLength += 1 + applicationProtocol.Length;
        }

        byte[] extension = new byte[2 + 2 + 2 + protocolListLength];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x0010);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + protocolListLength)));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)protocolListLength));
        index += 2;
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            extension[index++] = checked((byte)applicationProtocol.Length);
            applicationProtocol.CopyTo(extension.AsSpan(index));
            index += applicationProtocol.Length;
        }

        return extension;
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
        if (!QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            role,
            encodedTransportParameters,
            out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to format the representative transport parameters.");
        }

        byte[] extension = new byte[4 + bytesWritten];
        WriteUInt16(extension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        WriteUInt16(extension.AsSpan(2, 2), (ushort)bytesWritten);
        encodedTransportParameters.AsSpan(0, bytesWritten).CopyTo(extension.AsSpan(4));
        return extension;
    }

    private static byte[] CreateValidSecp256r1KeyShare(byte scalarTail)
    {
        using ECDiffieHellman clientKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        clientKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(scalarTail),
        });

        ECParameters parameters = clientKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[65];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
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
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
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

    private readonly record struct ClientHelloKeyShareEntry(
        ushort NamedGroup,
        byte[] KeyExchange);
}

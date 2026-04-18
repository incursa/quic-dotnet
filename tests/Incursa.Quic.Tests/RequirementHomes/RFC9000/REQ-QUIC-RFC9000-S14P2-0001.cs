namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0001">The UDP payload includes one or more QUIC packet headers and protected payloads.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0001")]
public sealed class REQ_QUIC_RFC9000_S14P2_0001
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] InitialSourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    private static readonly byte[] ApplicationDestinationConnectionId =
    [
        0x31, 0x32, 0x33, 0x34,
    ];

    private static readonly byte[] ApplicationSourceConnectionId =
    [
        0x41, 0x42, 0x43, 0x44,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedPackets_ProducePacketHeadersAndProtectedPayloads()
    {
        byte[] initialCryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20);
        byte[] handshakeCryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x20, 20);
        byte[] applicationPayload = QuicS12P3TestSupport.CreatePingPayload();
        byte[] expectedInitialFrame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, initialCryptoPayload));
        byte[] expectedHandshakeFrame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, handshakeCryptoPayload));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection initialProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection initialOpenProtection));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial handshakeMaterial));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        QuicHandshakeFlowCoordinator initialCoordinator = CreateInitialCoordinator();
        Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
            initialCryptoPayload,
            cryptoPayloadOffset: 0,
            initialProtection,
            out byte[] protectedInitialPacket));
        Assert.True(QuicPacketParser.TryParseLongHeader(protectedInitialPacket, out QuicLongHeaderPacket initialHeader));
        Assert.Equal((byte)QuicLongPacketTypeBits.Initial, initialHeader.LongPacketTypeBits);
        Assert.Equal(1u, initialHeader.Version);
        Assert.True(initialHeader.DestinationConnectionId.SequenceEqual(InitialDestinationConnectionId));
        Assert.True(initialHeader.SourceConnectionId.SequenceEqual(InitialSourceConnectionId));
        Assert.True(initialCoordinator.TryOpenInitialPacket(
            protectedInitialPacket,
            initialOpenProtection,
            out byte[] openedInitialPacket,
            out int initialPayloadOffset,
            out int initialPayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedInitialPacket.AsSpan(initialPayloadOffset, initialPayloadLength),
            out QuicCryptoFrame parsedInitialFrame,
            out int initialFrameBytesConsumed));
        Assert.Equal(expectedInitialFrame.Length, initialFrameBytesConsumed);
        Assert.True(parsedInitialFrame.CryptoData.SequenceEqual(initialCryptoPayload));

        QuicHandshakeFlowCoordinator handshakeCoordinator = CreateHandshakeCoordinator();
        Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
            handshakeCryptoPayload,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out byte[] protectedHandshakePacket));
        Assert.True(QuicPacketParser.TryParseLongHeader(protectedHandshakePacket, out QuicLongHeaderPacket handshakeHeader));
        Assert.Equal((byte)QuicLongPacketTypeBits.Handshake, handshakeHeader.LongPacketTypeBits);
        Assert.Equal(1u, handshakeHeader.Version);
        Assert.True(handshakeCoordinator.TryOpenHandshakePacket(
            protectedHandshakePacket,
            handshakeMaterial,
            out byte[] openedHandshakePacket,
            out int handshakePayloadOffset,
            out int handshakePayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedHandshakePacket.AsSpan(handshakePayloadOffset, handshakePayloadLength),
            out QuicCryptoFrame parsedHandshakeFrame,
            out int handshakeFrameBytesConsumed));
        Assert.Equal(expectedHandshakeFrame.Length, handshakeFrameBytesConsumed);
        Assert.True(parsedHandshakeFrame.CryptoData.SequenceEqual(handshakeCryptoPayload));

        QuicHandshakeFlowCoordinator applicationCoordinator = CreateApplicationCoordinator();
        Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            applicationMaterial,
            out byte[] protectedApplicationPacket));
        Assert.True(applicationCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedApplicationPacket,
            applicationMaterial,
            out byte[] openedApplicationPacket,
            out int applicationPayloadOffset,
            out int applicationPayloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedApplicationPacket, out _));
        Assert.True(QuicFrameCodec.TryParsePingFrame(
            openedApplicationPacket.AsSpan(applicationPayloadOffset, applicationPayloadLength),
            out int applicationBytesConsumed));
        Assert.Equal(applicationPayload.Length, applicationBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildProtectedPackets_RejectEmptyPayloads()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection initialProtection));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial handshakeMaterial));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        Assert.False(CreateInitialCoordinator().TryBuildProtectedInitialPacket(
            ReadOnlySpan<byte>.Empty,
            cryptoPayloadOffset: 0,
            initialProtection,
            out _));
        Assert.False(CreateHandshakeCoordinator().TryBuildProtectedHandshakePacket(
            ReadOnlySpan<byte>.Empty,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out _));
        Assert.False(CreateApplicationCoordinator().TryBuildProtectedApplicationDataPacket(
            ReadOnlySpan<byte>.Empty,
            applicationMaterial,
            out _));
    }

    private static QuicHandshakeFlowCoordinator CreateInitialCoordinator()
    {
        return new QuicHandshakeFlowCoordinator(InitialDestinationConnectionId, InitialSourceConnectionId);
    }

    private static QuicHandshakeFlowCoordinator CreateHandshakeCoordinator()
    {
        return new QuicHandshakeFlowCoordinator(InitialDestinationConnectionId, InitialSourceConnectionId);
    }

    private static QuicHandshakeFlowCoordinator CreateApplicationCoordinator()
    {
        return new QuicHandshakeFlowCoordinator(ApplicationDestinationConnectionId, ApplicationSourceConnectionId);
    }
}

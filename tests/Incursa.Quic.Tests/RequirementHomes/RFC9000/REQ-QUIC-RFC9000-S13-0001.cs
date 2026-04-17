namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13-0001">A sender MUST send one or more frames in a QUIC packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13-0001")]
public sealed class REQ_QUIC_RFC9000_S13_0001
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
    public void TryBuildProtectedPackets_KeepTheSuppliedFramePayloadIntact()
    {
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

        byte[] initialCryptoPayload = [0xA1];
        byte[] expectedInitialFrame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, initialCryptoPayload));
        QuicHandshakeFlowCoordinator initialCoordinator = CreateInitialCoordinator();
        Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
            initialCryptoPayload,
            cryptoPayloadOffset: 0,
            initialProtection,
            out byte[] protectedInitialPacket));
        Assert.True(initialCoordinator.TryOpenInitialPacket(
            protectedInitialPacket,
            initialOpenProtection,
            out byte[] openedInitialPacket,
            out int initialPayloadOffset,
            out int initialPayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedInitialPacket.AsSpan(initialPayloadOffset, initialPayloadLength),
            out QuicCryptoFrame parsedInitialFrame,
            out int initialBytesConsumed));
        Assert.Equal(expectedInitialFrame.Length, initialBytesConsumed);
        Assert.Equal(0UL, parsedInitialFrame.Offset);
        Assert.True(parsedInitialFrame.CryptoData.SequenceEqual(initialCryptoPayload));

        byte[] handshakeCryptoPayload = [0xB1];
        byte[] expectedHandshakeFrame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, handshakeCryptoPayload));
        QuicHandshakeFlowCoordinator handshakeCoordinator = CreateHandshakeCoordinator();
        Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
            handshakeCryptoPayload,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out byte[] protectedHandshakePacket));
        Assert.True(handshakeCoordinator.TryOpenHandshakePacket(
            protectedHandshakePacket,
            handshakeMaterial,
            out byte[] openedHandshakePacket,
            out int handshakePayloadOffset,
            out int handshakePayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedHandshakePacket.AsSpan(handshakePayloadOffset, handshakePayloadLength),
            out QuicCryptoFrame parsedHandshakeFrame,
            out int handshakeBytesConsumed));
        Assert.Equal(expectedHandshakeFrame.Length, handshakeBytesConsumed);
        Assert.Equal(0UL, parsedHandshakeFrame.Offset);
        Assert.True(parsedHandshakeFrame.CryptoData.SequenceEqual(handshakeCryptoPayload));

        byte[] applicationFramePayload = QuicFrameTestData.BuildPingFrame();
        QuicHandshakeFlowCoordinator applicationCoordinator = CreateApplicationCoordinator();
        Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationFramePayload,
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
        Assert.True(QuicFrameCodec.TryParsePingFrame(
            openedApplicationPacket.AsSpan(applicationPayloadOffset, applicationPayloadLength),
            out int applicationBytesConsumed));
        Assert.Equal(applicationFramePayload.Length, applicationBytesConsumed);
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

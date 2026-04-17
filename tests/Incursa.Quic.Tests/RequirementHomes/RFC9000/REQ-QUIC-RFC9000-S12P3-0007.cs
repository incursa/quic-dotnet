namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0007">Subsequent packets sent in the same packet number space MUST increase the packet number by at least one.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0007")]
public sealed class REQ_QUIC_RFC9000_S12P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketNumbersIncreaseByAtLeastOneInEachSpace()
    {
        byte[] initialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] initialSourceConnectionId =
        [
            0x01, 0x02, 0x03, 0x04,
        ];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDcid,
            out QuicInitialPacketProtection initialProtection));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial handshakeMaterial));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        QuicHandshakeFlowCoordinator initialCoordinator = new(initialDcid, initialSourceConnectionId);
        Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20),
            cryptoPayloadOffset: 0,
            initialProtection,
            out ulong firstInitialPacketNumber,
            out _));
        Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x20, 20),
            cryptoPayloadOffset: 20,
            initialProtection,
            out ulong secondInitialPacketNumber,
            out _));

        byte[] handshakeDestinationConnectionId =
        [
            0x11, 0x12, 0x13, 0x14,
        ];
        byte[] handshakeSourceConnectionId =
        [
            0x21, 0x22, 0x23, 0x24,
        ];
        QuicHandshakeFlowCoordinator handshakeCoordinator = new(
            handshakeDestinationConnectionId,
            handshakeSourceConnectionId);
        Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x30, 20),
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out ulong firstHandshakePacketNumber,
            out _));
        Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x40, 20),
            cryptoPayloadOffset: 20,
            handshakeMaterial,
            out ulong secondHandshakePacketNumber,
            out _));

        byte[] applicationDestinationConnectionId =
        [
            0x31, 0x32, 0x33, 0x34,
        ];
        byte[] applicationSourceConnectionId =
        [
            0x41, 0x42, 0x43, 0x44,
        ];
        QuicHandshakeFlowCoordinator applicationCoordinator = new(
            applicationDestinationConnectionId,
            applicationSourceConnectionId);
        Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            applicationMaterial,
            out ulong firstApplicationPacketNumber,
            out _));
        Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            applicationMaterial,
            out ulong secondApplicationPacketNumber,
            out _));

        Assert.Equal(0UL, firstInitialPacketNumber);
        Assert.Equal(1UL, secondInitialPacketNumber);
        Assert.Equal(0UL, firstHandshakePacketNumber);
        Assert.Equal(1UL, secondHandshakePacketNumber);
        Assert.Equal(0UL, firstApplicationPacketNumber);
        Assert.Equal(1UL, secondApplicationPacketNumber);
    }
}

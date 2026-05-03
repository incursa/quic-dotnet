namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0018">Handshake packets have their own packet number space, and thus the first Handshake packet sent by a server MUST contain a packet number of 0.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P4-0018")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FirstServerHandshakePacketStartsAtPacketNumberZero()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial handshakeMaterial));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateHandshakeCoordinator();
        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x50, 20);

        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out ulong firstPacketNumber,
            out byte[] firstProtectedPacket));
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out ulong secondPacketNumber,
            out byte[] secondProtectedPacket));

        Assert.Equal(0UL, firstPacketNumber);
        Assert.Equal(1UL, secondPacketNumber);

        Assert.True(coordinator.TryOpenHandshakePacket(
            firstProtectedPacket,
            handshakeMaterial,
            out byte[] openedFirstPacket,
            out int firstPayloadOffset,
            out _));
        Assert.True(coordinator.TryOpenHandshakePacket(
            secondProtectedPacket,
            handshakeMaterial,
            out byte[] openedSecondPacket,
            out int secondPayloadOffset,
            out _));

        Assert.Equal(0UL, QuicS17P1TestSupport.ReadPacketNumber(openedFirstPacket.AsSpan(firstPayloadOffset - 4, 4)));
        Assert.Equal(1UL, QuicS17P1TestSupport.ReadPacketNumber(openedSecondPacket.AsSpan(secondPayloadOffset - 4, 4)));
    }
}

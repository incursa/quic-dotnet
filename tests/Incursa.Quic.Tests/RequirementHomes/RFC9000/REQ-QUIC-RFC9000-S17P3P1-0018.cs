namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0018")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_RejectsTamperingAfterHeaderProtectionIsRemoved()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            out byte[] protectedPacket));

        byte[] tamperedPacket = protectedPacket.ToArray();
        tamperedPacket[^1] ^= 0x01;

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            tamperedPacket,
            material,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenProtectedApplicationDataPacket_RejectsTamperingAtTheShortestPacketNumberFieldLength()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            QuicS17P2P3TestSupport.PacketConnectionId,
            [0x00],
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            declaredPacketNumberLength: 1);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out _,
            out _,
            out _));

        byte[] tamperedPacket = protectedPacket.ToArray();
        tamperedPacket[^1] ^= 0x01;

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            tamperedPacket,
            material,
            out _,
            out _,
            out _));
    }
}

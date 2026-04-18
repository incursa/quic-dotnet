namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P1-0002">Prior to receiving an acknowledgment for a packet number space, the full packet number MUST be included; it is not to be truncated, as described below.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P1-0002")]
public sealed class REQ_QUIC_RFC9000_S17P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedInitialPacket_UsesFourBytePacketNumbersBeforeAnyAcknowledgment()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P1TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P1TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateInitialCoordinator();
        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x40, 20);

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out ulong firstPacketNumber,
            out byte[] firstProtectedPacket));
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out ulong secondPacketNumber,
            out byte[] secondProtectedPacket));

        Assert.Equal(0UL, firstPacketNumber);
        Assert.Equal(1UL, secondPacketNumber);
        AssertOpenedInitialPacketNumber(firstProtectedPacket, serverProtection, firstPacketNumber);
        AssertOpenedInitialPacketNumber(secondProtectedPacket, serverProtection, secondPacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedHandshakePacket_UsesFourBytePacketNumbersBeforeAnyAcknowledgment()
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
        AssertOpenedHandshakePacketNumber(firstProtectedPacket, handshakeMaterial, firstPacketNumber);
        AssertOpenedHandshakePacketNumber(secondProtectedPacket, handshakeMaterial, secondPacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenInitialPacket_RejectsTruncatedPackets()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P1TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P1TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateInitialCoordinator();
        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x40, 20);

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out byte[] protectedPacket));

        Assert.False(coordinator.TryOpenInitialPacket(
            protectedPacket[..^1],
            serverProtection,
            out _,
            out _,
            out _));
    }

    private static void AssertOpenedInitialPacketNumber(
        ReadOnlySpan<byte> protectedPacket,
        QuicInitialPacketProtection protection,
        ulong expectedPacketNumber)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateInitialCoordinator();

        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            protection,
            out byte[] openedPacket,
            out int payloadOffset,
            out _));
        Assert.Equal(expectedPacketNumber, QuicS17P1TestSupport.ReadPacketNumber(
            openedPacket.AsSpan(payloadOffset - 4, 4)));
    }

    private static void AssertOpenedHandshakePacketNumber(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        ulong expectedPacketNumber)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateHandshakeCoordinator();

        Assert.True(coordinator.TryOpenHandshakePacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out _));
        Assert.Equal(expectedPacketNumber, QuicS17P1TestSupport.ReadPacketNumber(
            openedPacket.AsSpan(payloadOffset - 4, 4)));
    }
}

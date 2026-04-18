namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0006")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P3_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientPacketNumbersContinueAcrossRetryForInitialAndZeroRttSpaces()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        byte[] firstInitialPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x60, 20);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            firstInitialPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out ulong firstInitialPacketNumber,
            out byte[] firstInitialPacket));
        Assert.Equal(0UL, firstInitialPacketNumber);

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out ulong firstZeroRttPacketNumber,
            out byte[] firstZeroRttPacket));
        Assert.Equal(0UL, firstZeroRttPacketNumber);

        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(QuicS17P2P5P2TestSupport.RetrySourceConnectionId));

        byte[] secondInitialPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x90, 24);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            secondInitialPayload,
            cryptoPayloadOffset: 0,
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            QuicS17P2P5P2TestSupport.RetryToken,
            clientProtection,
            out ulong secondInitialPacketNumber,
            out byte[] secondInitialPacket));
        Assert.Equal(1UL, secondInitialPacketNumber);

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out ulong secondZeroRttPacketNumber,
            out byte[] secondZeroRttPacket));
        Assert.Equal(1UL, secondZeroRttPacketNumber);

        Assert.True(firstInitialPacket.Length > 0);
        Assert.True(firstZeroRttPacket.Length > 0);
        Assert.True(secondInitialPacket.Length > 0);
        Assert.True(secondZeroRttPacket.Length > 0);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P3-0003")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttPacketsCanCarryEarlyDataPayloadInTheFirstFlight()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);

        byte[] earlyDataPayload = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 1,
            QuicS17P2P3TestSupport.CreateSequentialBytes(0xA0, 32),
            offset: 0);

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreateBootstrapPacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            earlyDataPayload,
            zeroRttMaterial,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.Equal(0UL, packetNumber);
        Assert.True(QuicS17P2P3TestSupport.IsZeroRttPacket(protectedPacket));
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            protectedPacket,
            out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
        Assert.True(protectedPacket.Length > QuicS17P2P3TestSupport.BuildExpectedZeroRttPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial).Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZeroRttPacketBuilderRejectsEmptyPayloadsAndWrongEncryptionLevel()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        QuicTlsPacketProtectionMaterial oneRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        byte[] earlyDataPayload = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 1,
            QuicS17P2P3TestSupport.CreateSequentialBytes(0xA0, 32),
            offset: 0);

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreateBootstrapPacketCoordinator();
        Assert.False(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            ReadOnlySpan<byte>.Empty,
            zeroRttMaterial,
            out _,
            out _));
        Assert.False(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            earlyDataPayload,
            oneRttMaterial,
            out _,
            out _));
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P3-0018")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttPacketNumbersAdvanceMonotonicallyAcrossBackToBackEmissions()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreateBootstrapPacketCoordinator();

        byte[] firstPayload = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 1,
            QuicS17P2P3TestSupport.CreateSequentialBytes(0x10, 16),
            offset: 0);
        byte[] secondPayload = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 3,
            QuicS17P2P3TestSupport.CreateSequentialBytes(0x20, 24),
            offset: 0);

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            firstPayload,
            zeroRttMaterial,
            out ulong firstPacketNumber,
            out byte[] firstPacket));
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            secondPayload,
            zeroRttMaterial,
            out ulong secondPacketNumber,
            out byte[] secondPacket));

        Assert.Equal(0UL, firstPacketNumber);
        Assert.Equal(1UL, secondPacketNumber);
        Assert.True(QuicS17P2P3TestSupport.IsZeroRttPacket(firstPacket));
        Assert.True(QuicS17P2P3TestSupport.IsZeroRttPacket(secondPacket));
        Assert.False(firstPacket.AsSpan().SequenceEqual(secondPacket));
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
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreateBootstrapPacketCoordinator();

        Assert.False(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            ReadOnlySpan<byte>.Empty,
            zeroRttMaterial,
            out _,
            out _));
        Assert.False(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicFrameTestData.BuildPingFrame(),
            oneRttMaterial,
            out _,
            out _));
    }
}

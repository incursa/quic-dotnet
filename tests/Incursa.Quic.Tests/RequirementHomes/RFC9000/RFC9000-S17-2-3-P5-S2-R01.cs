// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S17-2-3-P5-S2-R01")]
public sealed class RFC9000_S17_2_3_P5_S2_R01
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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroRttPacketNumberFuzz_UsesFreshPacketNumbersForEachEmission()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreateBootstrapPacketCoordinator();
        HashSet<ulong> observedPacketNumbers = [];
        List<byte[]> emittedPackets = [];

        for (int emissionIndex = 0; emissionIndex < 8; emissionIndex++)
        {
            byte[] payload = QuicStreamTestData.BuildStreamFrame(
                0x0E,
                streamId: (ulong)((emissionIndex * 4) + 1),
                QuicS17P2P3TestSupport.CreateSequentialBytes((byte)(0x30 + emissionIndex), 8 + emissionIndex),
                offset: (ulong)emissionIndex);

            Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
                payload,
                zeroRttMaterial,
                out ulong packetNumber,
                out byte[] packet));

            Assert.Equal((ulong)emissionIndex, packetNumber);
            Assert.True(observedPacketNumbers.Add(packetNumber));
            Assert.True(QuicS17P2P3TestSupport.IsZeroRttPacket(packet));
            Assert.DoesNotContain(emittedPackets, previousPacket => previousPacket.AsSpan().SequenceEqual(packet));
            emittedPackets.Add(packet);
        }
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S17-2-5-3-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_1053
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("RFC9000-S17-2-5-3-P4-S1-R01")]
    public void ClientInitialPacketNumberDoesNotRestartAtZeroAfterRetry()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x60, 20),
            cryptoPayloadOffset: 0,
            clientProtection,
            out ulong firstInitialPacketNumber,
            out _));
        Assert.Equal(0UL, firstInitialPacketNumber);

        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(QuicS17P2P5P2TestSupport.RetrySourceConnectionId));
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x90, 24),
            cryptoPayloadOffset: 0,
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            QuicS17P2P5P2TestSupport.RetryToken,
            clientProtection,
            out ulong postRetryInitialPacketNumber,
            out _));

        Assert.NotEqual(0UL, postRetryInitialPacketNumber);
        Assert.Equal(1UL, postRetryInitialPacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("RFC9000-S17-2-5-3-P4-S1-R01")]
    public void ClientPacketNumbersContinueAcrossRetryAfterMultipleInitialAndZeroRttPackets()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        for (int packetIndex = 0; packetIndex < 2; packetIndex++)
        {
            Assert.True(coordinator.TryBuildProtectedInitialPacket(
                QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x60 + packetIndex), 20),
                cryptoPayloadOffset: (ulong)(packetIndex * 20),
                clientProtection,
                out ulong initialPacketNumber,
                out _));
            Assert.Equal((ulong)packetIndex, initialPacketNumber);

            Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
                QuicS17P2P3TestSupport.CreatePingPayload(),
                zeroRttMaterial,
                out ulong zeroRttPacketNumber,
                out _));
            Assert.Equal((ulong)packetIndex, zeroRttPacketNumber);
        }

        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(QuicS17P2P5P2TestSupport.RetrySourceConnectionId));
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x90, 24),
            cryptoPayloadOffset: 40,
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            QuicS17P2P5P2TestSupport.RetryToken,
            clientProtection,
            out ulong postRetryInitialPacketNumber,
            out _));
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out ulong postRetryZeroRttPacketNumber,
            out _));

        Assert.Equal(2UL, postRetryInitialPacketNumber);
        Assert.Equal(2UL, postRetryZeroRttPacketNumber);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("RFC9000-S17-2-5-3-P4-S1-R01")]
    public void Fuzz_ClientPacketNumbersContinueAcrossRetryWithoutResettingPacketNumberSpaces(
        int packetsBeforeRetry)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        for (int packetIndex = 0; packetIndex < packetsBeforeRetry; packetIndex++)
        {
            Assert.True(coordinator.TryBuildProtectedInitialPacket(
                QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x60 + packetIndex), 20 + packetIndex),
                cryptoPayloadOffset: (ulong)(packetIndex * 7),
                clientProtection,
                out ulong initialPacketNumber,
                out _));
            Assert.Equal((ulong)packetIndex, initialPacketNumber);

            Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
                QuicS17P2P3TestSupport.CreatePingPayload(),
                zeroRttMaterial,
                out ulong zeroRttPacketNumber,
                out _));
            Assert.Equal((ulong)packetIndex, zeroRttPacketNumber);
        }

        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(QuicS17P2P5P2TestSupport.RetrySourceConnectionId));

        for (int postRetryIndex = 0; postRetryIndex < 3; postRetryIndex++)
        {
            ulong expectedPacketNumber = (ulong)(packetsBeforeRetry + postRetryIndex);
            Assert.True(coordinator.TryBuildProtectedInitialPacket(
                QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x90 + postRetryIndex), 24 + postRetryIndex),
                cryptoPayloadOffset: (ulong)(packetsBeforeRetry * 11 + postRetryIndex),
                QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
                QuicS17P2P5P2TestSupport.RetryToken,
                clientProtection,
                out ulong postRetryInitialPacketNumber,
                out _));
            Assert.Equal(expectedPacketNumber, postRetryInitialPacketNumber);

            Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
                QuicS17P2P3TestSupport.CreatePingPayload(),
                zeroRttMaterial,
                out ulong postRetryZeroRttPacketNumber,
                out _));
            Assert.Equal(expectedPacketNumber, postRetryZeroRttPacketNumber);
        }
    }
}

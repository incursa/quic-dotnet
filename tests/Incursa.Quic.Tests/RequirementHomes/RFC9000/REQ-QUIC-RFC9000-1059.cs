// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1059")]
public sealed class REQ_QUIC_RFC9000_1059
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-1059")]
    public void TryBuildProtectedApplicationDataPacket_RejectsNonOneRttPacketProtection()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake);

        Assert.False(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_EmitsAShortHeaderOnceOneRttKeysAreAvailable()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(openedPacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
        Assert.Equal(1 + QuicS17P2P3TestSupport.PacketConnectionId.Length + 4, payloadOffset);
        Assert.True(payloadLength >= payload.Length);
    }
}

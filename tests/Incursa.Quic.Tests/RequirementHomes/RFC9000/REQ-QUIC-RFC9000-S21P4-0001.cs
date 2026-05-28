// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S21P4-0001")]
public sealed class REQ_QUIC_RFC9000_S21P4_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S21P4-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandshakePacketNumbersCanBeSkippedWhenTheCoordinatorCounterAdvances()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateHandshakeCoordinator();
        QuicTlsPacketProtectionMaterial handshakeMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake);
        byte[] payload = QuicS17P2P3TestSupport.CreateSequentialBytes(0x10, 16);

        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            payload,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out ulong firstPacketNumber,
            out _));

        QuicS17P1TestSupport.SetNextHandshakePacketNumber(coordinator, firstPacketNumber + 4);

        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            payload,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out ulong skippedPacketNumber,
            out _));

        Assert.Equal(0UL, firstPacketNumber);
        Assert.Equal(4UL, skippedPacketNumber);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S21P4-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PacketNumbersStayContiguousUnlessTheCoordinatorCounterIsAdvanced()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateHandshakeCoordinator();
        QuicTlsPacketProtectionMaterial handshakeMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake);
        byte[] payload = QuicS17P2P3TestSupport.CreateSequentialBytes(0x20, 16);

        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            payload,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out ulong firstPacketNumber,
            out _));
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            payload,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out ulong secondPacketNumber,
            out _));

        Assert.Equal(0UL, firstPacketNumber);
        Assert.Equal(1UL, secondPacketNumber);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S21P4-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ApplicationPacketNumbersCanSkipToTheFourByteBoundary()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateApplicationCoordinator();
        QuicTlsPacketProtectionMaterial oneRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS17P2P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            oneRttMaterial,
            out ulong firstPacketNumber,
            out _));

        QuicS17P1TestSupport.SetNextApplicationPacketNumber(coordinator, uint.MaxValue);

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            oneRttMaterial,
            out ulong skippedPacketNumber,
            out _));

        Assert.Equal(0UL, firstPacketNumber);
        Assert.Equal((ulong)uint.MaxValue, skippedPacketNumber);
    }
}

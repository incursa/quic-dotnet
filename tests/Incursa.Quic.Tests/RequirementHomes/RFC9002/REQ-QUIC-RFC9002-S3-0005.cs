// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S3-0005")]
public sealed class REQ_QUIC_RFC9002_S3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_DoesNotReusePacketNumbersWithinOneSpace()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS17P2P3TestSupport.CreatePingPayload();
        HashSet<ulong> packetNumbers = [];

        for (int index = 0; index < 4; index++)
        {
            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                payload,
                material,
                out ulong packetNumber,
                out byte[] protectedPacket));
            Assert.NotEmpty(protectedPacket);
            Assert.True(packetNumbers.Add(packetNumber));
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildProtectedApplicationDataPacketForRetransmission_DoesNotReuseAnIssuedPacketNumber()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS17P2P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out ulong originalPacketNumber,
            out byte[] originalPacket));
        Assert.NotEmpty(originalPacket);

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            payload,
            minimumPacketNumberExclusive: originalPacketNumber,
            material,
            keyPhase: false,
            out ulong retransmissionPacketNumber,
            out byte[] retransmissionPacket));

        Assert.NotEmpty(retransmissionPacket);
        Assert.NotEqual(originalPacketNumber, retransmissionPacketNumber);
        Assert.True(retransmissionPacketNumber > originalPacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildProtectedApplicationDataPacketForRetransmission_RejectsExhaustedPacketNumberSpaceWithoutReuse()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS17P2P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            payload,
            minimumPacketNumberExclusive: QuicVariableLengthInteger.MaxValue - 2,
            material,
            keyPhase: false,
            out ulong finalPacketNumber,
            out byte[] finalPacket));

        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, finalPacketNumber);
        Assert.NotEmpty(finalPacket);

        Assert.False(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out ulong rejectedPacketNumber,
            out byte[] rejectedPacket));
        Assert.Equal(0UL, rejectedPacketNumber);
        Assert.Empty(rejectedPacket);
    }
}

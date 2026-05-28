// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0023">1-RTT packets always MUST include a 1-RTT protected payload.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P3P1-0023")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0023
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildProtectedApplicationDataPacket_RejectsEmptyPayloads()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        Assert.False(coordinator.TryBuildProtectedApplicationDataPacket(
            ReadOnlySpan<byte>.Empty,
            material,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_CarriesTheApplicationPayload()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] applicationPayload = QuicS12P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            material,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(payloadLength >= applicationPayload.Length);
        Assert.True(openedPacket.AsSpan(payloadOffset, applicationPayload.Length).SequenceEqual(applicationPayload));
        Assert.True(openedPacket.AsSpan(payloadOffset + applicationPayload.Length, payloadLength - applicationPayload.Length)
            .SequenceEqual(new byte[payloadLength - applicationPayload.Length]));
    }
}

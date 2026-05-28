// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1090">When the spin bit is disabled, endpoints MAY set the spin bit to any value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1090")]
public sealed class REQ_QUIC_RFC9000_1090
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1090">When the spin bit is disabled, endpoints MAY set the spin bit to any value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1090")]
    public void TryBuildProtectedApplicationDataPacket_UsesTheClearedSpinBitWhenDisabled()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        byte[] destinationConnectionId = [0x11, 0x31];
        byte[] sourceConnectionId = [0x50];
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId, sourceConnectionId);

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
        Assert.False(header.SpinBit);
        Assert.Equal(1 + destinationConnectionId.Length + 4, payloadOffset);
        Assert.True(payloadLength >= payload.Length);
        Assert.True(openedPacket.AsSpan(payloadOffset, payload.Length).SequenceEqual(payload));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1090">When the spin bit is disabled, endpoints MAY set the spin bit to any value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1090")]
    public void TryBuildProtectedApplicationDataPacket_DoesNotClearRequestedSpinBitWhenSelectionAllowsIt()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        byte[] destinationConnectionId = [0x11, 0x31];
        byte[] sourceConnectionId = [0x50];
        QuicHandshakeFlowCoordinator coordinator = new(
            destinationConnectionId,
            sourceConnectionId,
            enableRandomizedSpinBitSelection: true);

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
        Assert.True(header.SpinBit);
        Assert.Equal(1 + destinationConnectionId.Length + 4, payloadOffset);
        Assert.True(payloadLength >= payload.Length);
        Assert.True(openedPacket.AsSpan(payloadOffset, payload.Length).SequenceEqual(payload));
    }
}

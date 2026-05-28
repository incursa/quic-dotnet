// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1011">An acknowledgment for a 1-RTT packet MUST be carried in a 1-RTT packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1011")]
public sealed class REQ_QUIC_RFC9000_1011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-1011")]
    public void AckResponsePayloadIsNotOpenedWithHandshakePacketProtection()
    {
        byte[] ackResponsePayload = QuicS17P2P3TestSupport.CreateAckResponsePayload();
        QuicTlsPacketProtectionMaterial oneRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        QuicTlsPacketProtectionMaterial handshakeMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();

        byte[] oneRttPacket = QuicS17P2P3TestSupport.BuildExpectedOneRttPacket(
            ackResponsePayload,
            oneRttMaterial,
            keyPhase: false);

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            oneRttPacket,
            handshakeMaterial,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AckResponsePayloadIsBuiltAsAOneRttPacket()
    {
        byte[] ackResponsePayload = QuicS17P2P3TestSupport.CreateAckResponsePayload();
        Assert.True(QuicFrameCodec.TryParseAckFrame(ackResponsePayload, out _, out _));

        QuicTlsPacketProtectionMaterial oneRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        byte[] oneRttPacket = QuicS17P2P3TestSupport.BuildExpectedOneRttPacket(
            ackResponsePayload,
            oneRttMaterial,
            keyPhase: false);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            oneRttPacket,
            oneRttMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket shortHeader));
        Assert.True(shortHeader.FixedBit);
        Assert.True(QuicFrameCodec.TryParseAckFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicAckFrame parsedAckFrame,
            out _));
        Assert.Equal(0UL, parsedAckFrame.LargestAcknowledged);
    }
}

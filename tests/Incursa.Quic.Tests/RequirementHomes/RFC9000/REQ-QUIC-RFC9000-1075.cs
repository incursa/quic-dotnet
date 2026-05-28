// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1075">The least significant two bits (those with a mask of 0x03) of byte 0 MUST contain the length of the Packet Number field, encoded as an unsigned two-bit integer that is one less than the length of the Packet Number field in bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1075")]
public sealed class REQ_QUIC_RFC9000_1075
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_EncodesThePacketNumberLengthAsOneLessThanTheFieldLength()
    {
        byte[] remainder = [0xA1, 0xB2, 0xC3];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x02, remainder);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
        Assert.True(packet.AsSpan(1).SequenceEqual(header.Remainder));
        Assert.Equal(remainder.Length, header.Remainder.Length);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenProtectedApplicationDataPacket_EncodesTheBoundaryPacketNumberLengthBits(int packetNumberLength)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();
        byte[] packetNumber = new byte[packetNumberLength];

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            QuicS17P2P3TestSupport.PacketConnectionId,
            packetNumber,
            payload,
            material,
            declaredPacketNumberLength: packetNumberLength);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
        Assert.Equal(1 + QuicS17P2P3TestSupport.PacketConnectionId.Length + packetNumberLength, payloadOffset);
        Assert.Equal(0UL, QuicS17P1TestSupport.ReadPacketNumber(
            openedPacket.AsSpan(payloadOffset - packetNumberLength, packetNumberLength)));
        Assert.True(payloadLength >= payload.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_RejectsPacketNumberLengthEncodingMismatches()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            QuicS17P2P3TestSupport.PacketConnectionId,
            [0x00],
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            declaredPacketNumberLength: 4);

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out _,
            out _,
            out _));
    }
}

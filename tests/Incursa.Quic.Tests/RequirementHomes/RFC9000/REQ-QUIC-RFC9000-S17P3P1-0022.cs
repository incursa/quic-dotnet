// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0022">The length of the Packet Number field MUST be encoded in Packet Number Length field.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P3P1-0022")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0022
{
    public static TheoryData<int> PacketNumberLengthCases => new()
    {
        { 1 },
        { 2 },
        { 3 },
        { 4 },
    };

    [Theory]
    [MemberData(nameof(PacketNumberLengthCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_EncodesThePacketNumberLengthAsOneLessThanTheFieldLength(int packetNumberLength)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        byte[] packetNumber = new byte[packetNumberLength];
        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            QuicS17P2P3TestSupport.PacketConnectionId,
            packetNumber,
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            declaredPacketNumberLength: packetNumberLength);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out _,
            out _));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
    }

    public static TheoryData<int> BoundaryPacketNumberLengthCases => new()
    {
        { 1 },
        { 4 },
    };

    [Theory]
    [MemberData(nameof(BoundaryPacketNumberLengthCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseShortHeader_EncodesTheBoundaryPacketNumberLengthValues(int packetNumberLength)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        byte[] packetNumber = new byte[packetNumberLength];
        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            QuicS17P2P3TestSupport.PacketConnectionId,
            packetNumber,
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            declaredPacketNumberLength: packetNumberLength);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out _,
            out _));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_RejectsPacketNumberLengthMismatches()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            QuicS17P2P3TestSupport.PacketConnectionId,
            [0x01, 0x02, 0x03, 0x04],
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            declaredPacketNumberLength: 1);

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out _,
            out _,
            out _));
    }
}

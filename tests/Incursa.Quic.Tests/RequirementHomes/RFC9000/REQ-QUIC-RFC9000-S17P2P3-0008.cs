// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0008">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0008")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesTheReservedBits()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x59,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.ReservedBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_DoesNotIncludePacketNumberLengthBitsInTheReservedBits()
    {
        byte[] packet = QuicS17P2P3TestSupport.BuildZeroRttPacket(
            packetNumberLength: 4,
            reservedBits: 0x00);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x00, header.ReservedBits);
        Assert.Equal((byte)0x03, header.PacketNumberLengthBits);
    }
}

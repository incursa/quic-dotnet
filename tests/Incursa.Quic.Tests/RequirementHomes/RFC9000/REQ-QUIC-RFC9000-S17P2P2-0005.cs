// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0005")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesTheInitialReservedBits()
    {
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(
            packetNumberLength: 2,
            reservedBits: 0x02);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.ReservedBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_DoesNotIncludePacketNumberLengthBitsInTheReservedBits()
    {
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(
            packetNumberLength: 4,
            reservedBits: 0x00);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x00, header.ReservedBits);
        Assert.Equal((byte)0x03, header.PacketNumberLengthBits);
    }
}

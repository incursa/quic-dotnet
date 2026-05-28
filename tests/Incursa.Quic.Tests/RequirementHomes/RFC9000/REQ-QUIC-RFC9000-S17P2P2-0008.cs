// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0008")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_PreservesTheDestinationConnectionIdLengthByte()
    {
        byte[] destinationConnectionId = [0x10, 0x11, 0x12];
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(destinationConnectionId: destinationConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsPacketsMissingTheDestinationConnectionIdLengthByte()
    {
        byte[] packet =
        [
            0xC0,
            0x00, 0x00, 0x00, 0x01,
        ];

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsDestinationConnectionIdLengthByteBoundaries(int destinationConnectionIdLength)
    {
        byte[] destinationConnectionId = new byte[destinationConnectionIdLength];
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(destinationConnectionId: destinationConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionIdLength);
    }
}

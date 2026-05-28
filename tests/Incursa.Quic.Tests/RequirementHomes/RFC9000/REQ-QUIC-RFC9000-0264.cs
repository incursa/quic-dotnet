// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0264")]
public sealed class REQ_QUIC_RFC9000_0264
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_AcceptsVersion1Packets()
    {
        byte[] packet = BuildSelectedVersionPacket(version: 1);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(1u, header.Version);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_RejectsPacketsWithDifferentSelectedVersions()
    {
        byte[] packet = BuildSelectedVersionPacket(version: 2);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(2u, header.Version);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(packet, out _));
    }

    private static byte[] BuildSelectedVersionPacket(uint version)
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: version,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], [0xAA]));
    }
}

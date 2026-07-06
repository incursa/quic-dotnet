// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-2-P6-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0258
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsValidInitialPacketWithPacketNumberSpace()
    {
        byte[] initialPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [0x01],
                packetNumber: [0x02],
                protectedPayload: [0xAA, 0xBB]));

        Assert.True(QuicPacketParser.TryParseLongHeader(initialPacket, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsWeaklyProtectedInvalidPackets()
    {
        byte[] truncatedInitialPacket = QuicHeaderTestData.BuildTruncatedLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([0x01], [0x02], [0xAA]),
            truncateBy: 1);

        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x70,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30]);

        Assert.False(QuicPacketParser.TryParseLongHeader(truncatedInitialPacket, out _));
        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket retryHeader));
        Assert.Equal((byte)0x03, retryHeader.LongPacketTypeBits);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryParseLongHeaderFuzz_RejectsInvalidWeaklyProtectedPackets()
    {
        byte[][] invalidPackets =
        [
            QuicHeaderTestData.BuildTruncatedLongHeader(
                headerControlBits: 0x40,
                version: 1,
                destinationConnectionId: [0x10],
                sourceConnectionId: [0x20],
                versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([0x01], [0x02], [0xAA]),
                truncateBy: 1),
            QuicHeaderTestData.BuildTruncatedLongHeader(
                headerControlBits: 0x60,
                version: 1,
                destinationConnectionId: [0x11, 0x12],
                sourceConnectionId: [0x21, 0x22],
                versionSpecificData: [0x30, 0x31],
                truncateBy: 2),
            QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x70,
                version: 1,
                destinationConnectionId: [0x13],
                sourceConnectionId: [0x23],
                versionSpecificData: [0x33]),
            QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x80,
                version: 0,
                destinationConnectionId: [0x14],
                sourceConnectionId: [0x24],
                versionSpecificData: [0x34, 0x35]),
        ];

        foreach (byte[] invalidPacket in invalidPackets)
        {
            Assert.False(QuicPacketParser.TryGetPacketNumberSpace(invalidPacket, out _));
        }
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P1-0001">When present in long or short packet headers, they MUST be encoded in 1 to 4 bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P1-0001")]
public sealed class REQ_QUIC_RFC9000_S17P1_0001
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
    public void TryParseLongHeader_AllowsPacketNumberFieldsFromOneToFourBytes(int packetNumberLength)
    {
        byte[] packetNumber = CreatePacketNumber(packetNumberLength);
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber,
            protectedPayload: [0xBB]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask | ((packetNumberLength - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask)),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Theory]
    [MemberData(nameof(PacketNumberLengthCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_AllowsPacketNumberFieldsFromOneToFourBytes(int packetNumberLength)
    {
        byte[] packetNumber = CreatePacketNumber(packetNumberLength);
        byte[] packet = QuicHeaderTestData.BuildShortHeader((byte)(packetNumberLength - 1), packetNumber);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
        Assert.True(packetNumber.AsSpan().SequenceEqual(header.Remainder));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsPacketsTruncatedBeforeThePacketNumberFieldCompletes()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01, 0x02, 0x03, 0x04],
            protectedPayload: [0xBB]);
        byte[] packet = QuicHeaderTestData.BuildTruncatedLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask | 0x03),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData,
            truncateBy: 1);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryParsePacketHeaders_FuzzPreservesEncodedPacketNumberLengths()
    {
        for (int packetNumberLength = 1; packetNumberLength <= 4; packetNumberLength++)
        {
            byte[] packetNumber = CreatePacketNumber(packetNumberLength);
            byte packetNumberLengthBits = (byte)(packetNumberLength - 1);
            byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [(byte)packetNumberLength],
                packetNumber,
                protectedPayload: [0xBB, (byte)(0xC0 | packetNumberLength)]);
            byte[] longHeaderPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask | packetNumberLengthBits),
                version: 1,
                destinationConnectionId: [0x10, (byte)packetNumberLength],
                sourceConnectionId: [0x20],
                versionSpecificData);
            byte[] shortHeaderPacket = QuicHeaderTestData.BuildShortHeader(packetNumberLengthBits, packetNumber);

            Assert.True(QuicPacketParser.TryParseLongHeader(longHeaderPacket, out QuicLongHeaderPacket longHeader));
            Assert.Equal(packetNumberLengthBits, longHeader.PacketNumberLengthBits);
            Assert.True(versionSpecificData.AsSpan().SequenceEqual(longHeader.VersionSpecificData));

            Assert.True(QuicPacketParser.TryParseShortHeader(shortHeaderPacket, out QuicShortHeaderPacket shortHeader));
            Assert.Equal(packetNumberLengthBits, shortHeader.PacketNumberLengthBits);
            Assert.True(packetNumber.AsSpan().SequenceEqual(shortHeader.Remainder));
        }
    }

    private static byte[] CreatePacketNumber(int packetNumberLength)
    {
        return Enumerable.Range(0, packetNumberLength)
            .Select(index => (byte)(index + 1))
            .ToArray();
    }
}

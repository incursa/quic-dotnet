// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S3-P1-S2-R01">The encryption level MUST indicate the packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S3-P1-S2-R01")]
public sealed class RFC9002_S3_P1_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetPacketNumberSpace_MapsSupportedEncryptionLevelsToPacketNumberSpaces()
    {
        byte[] initialPacket = QuicHeaderTestData.BuildLongHeader(
            (byte)(QuicPacketHeaderBits.FixedBitMask | (QuicLongPacketTypeBits.Initial << QuicPacketHeaderBits.LongPacketTypeBitsShift)),
            version: 1,
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0xA1], [0xB2]));
        byte[] handshakePacket = QuicHeaderTestData.BuildLongHeader(
            (byte)(QuicPacketHeaderBits.FixedBitMask | (QuicLongPacketTypeBits.Handshake << QuicPacketHeaderBits.LongPacketTypeBitsShift)),
            version: 1,
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02],
            versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData([0xA1], [0xB2]));
        byte[] applicationDataPacket = QuicHeaderTestData.BuildShortHeader(0x00, [0xA1]);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationDataPacket, out QuicPacketNumberSpace applicationDataSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationDataSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGetPacketNumberSpace_RejectsVersionNegotiationPackets()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            QuicPacketHeaderBits.FixedBitMask,
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02],
            supportedVersions: 1);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9002-S3-P1-S2-R01">The encryption level MUST indicate the packet number space.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9002-S3-P1-S2-R01")]
    public void TryGetPacketNumberSpace_AcceptsTheShortestValidShortHeader()
    {
        byte[] packet = [0x40];

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryGetPacketNumberSpace_MapsEncryptionLevelAcrossSupportedPacketEncodings()
    {
        foreach ((uint version, QuicLongPacketType packetType, QuicPacketNumberSpace expectedSpace) in new[]
        {
            (QuicVersionNegotiation.Version1, QuicLongPacketType.Initial, QuicPacketNumberSpace.Initial),
            (QuicVersionNegotiation.Version1, QuicLongPacketType.ZeroRtt, QuicPacketNumberSpace.ApplicationData),
            (QuicVersionNegotiation.Version1, QuicLongPacketType.Handshake, QuicPacketNumberSpace.Handshake),
            (QuicVersionNegotiation.Version2, QuicLongPacketType.Initial, QuicPacketNumberSpace.Initial),
            (QuicVersionNegotiation.Version2, QuicLongPacketType.ZeroRtt, QuicPacketNumberSpace.ApplicationData),
            (QuicVersionNegotiation.Version2, QuicLongPacketType.Handshake, QuicPacketNumberSpace.Handshake),
        })
        {
            byte[] packet = BuildLongHeaderPacketForMapping(version, packetType);

            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
            Assert.Equal(expectedSpace, packetNumberSpace);
        }

        foreach (byte shortHeaderControlBits in new byte[] { 0x00, 0x01, 0x1F, 0x3F })
        {
            byte[] packet = QuicHeaderTestData.BuildShortHeader(shortHeaderControlBits, [0xA1, 0xB2]);

            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
            Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
        }
    }

    private static byte[] BuildLongHeaderPacketForMapping(uint version, QuicLongPacketType packetType)
    {
        byte longHeaderPacketTypeBits = QuicVersionNegotiation.GetLongHeaderPacketTypeBits(version, packetType);
        byte headerControlBits = (byte)(QuicPacketHeaderBits.FixedBitMask
            | (longHeaderPacketTypeBits << QuicPacketHeaderBits.LongPacketTypeBitsShift));
        byte[] versionSpecificData = packetType == QuicLongPacketType.Initial
            ? QuicHeaderTestData.BuildInitialVersionSpecificData([], [0xA1], [0xB2])
            : QuicHeaderTestData.BuildZeroRttVersionSpecificData([0xA1], [0xB2]);

        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version,
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02],
            versionSpecificData);
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0004">The encryption level MUST indicate the packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0004")]
public sealed class REQ_QUIC_RFC9002_S3_0004
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
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0004">The encryption level MUST indicate the packet number space.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    public void TryGetPacketNumberSpace_AcceptsTheShortestValidShortHeader()
    {
        byte[] packet = [0x40];

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
    }
}

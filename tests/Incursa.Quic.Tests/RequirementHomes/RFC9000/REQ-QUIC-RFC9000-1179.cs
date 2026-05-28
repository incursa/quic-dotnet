// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1179")]
public sealed class REQ_QUIC_RFC9000_1179
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1179")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_DoesNotAssignAckSpaceToPacketsWithoutPacketNumbers()
    {
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [1, 2]);

        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x70,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30]);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1179")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_RejectsVersionNegotiationAndRetryBeforeAckProcessing()
    {
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [1, 2]);

        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x70,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30]);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }
}

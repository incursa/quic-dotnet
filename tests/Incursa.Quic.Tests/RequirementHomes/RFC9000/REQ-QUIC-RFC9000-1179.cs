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

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1179")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationAndRetryPacketsNeverEnterAnAckPacketNumberSpace()
    {
        for (int i = 0; i < 32; i++)
        {
            byte[] destinationConnectionId = Enumerable.Range(0, i % 9)
                .Select(value => (byte)(0x10 + i + value))
                .ToArray();
            byte[] sourceConnectionId = Enumerable.Range(0, i % 7)
                .Select(value => (byte)(0x40 + i + value))
                .ToArray();

            byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits: (byte)(0x40 | (i & 0x3F)),
                destinationConnectionId,
                sourceConnectionId,
                supportedVersions: [1, (uint)(0xA0A0_0000 + i)]);

            byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x70,
                version: 1,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData: [(byte)(0x80 + i), (byte)(0x90 + i)]);

            Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));
            Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
        }
    }
}

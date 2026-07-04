// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S15-P7-S1-R03">Reserved version numbers MUST NOT represent a real protocol.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S15-P7-S1-R03")]
public sealed class RFC9000_S15_P7_S1_R03
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ParsesReservedVersionPacketsAsLongHeaders()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4C,
            version: reservedVersion,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30, 0x31]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(reservedVersion, header.Version);
        Assert.False(header.IsVersionNegotiation);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_RejectsPacketsWithReservedVersions()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4C,
            version: reservedVersion,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30, 0x31]);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet, out _));
    }
}

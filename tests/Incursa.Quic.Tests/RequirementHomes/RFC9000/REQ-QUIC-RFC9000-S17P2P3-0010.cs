// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0010">The Version field MUST be 32 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0010")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesTheVersionField()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x55,
            version: 0x11223344,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0x11223344u, header.Version);
    }
}

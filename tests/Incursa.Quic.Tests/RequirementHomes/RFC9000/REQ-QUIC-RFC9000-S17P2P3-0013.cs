// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0013">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0013")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesTheSourceConnectionIdLengthField()
    {
        byte[] sourceConnectionId =
        [
            0x20, 0x21, 0x22, 0x23,
        ];

        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x55,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsZeroRttPacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: QuicS17P2P3TestSupport.BuildZeroRttHeaderControlBits(),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicS17P2P3TestSupport.BuildZeroRttVersionSpecificData(packetNumberLength: 2));

        Array.Resize(ref packet, 6 + packet[5]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_ExposesZeroRttSourceConnectionIdLengthBoundaries(int sourceConnectionIdLength)
    {
        byte[] packet = QuicS17P2P3TestSupport.BuildZeroRttPacket(
            destinationConnectionId: [0x10],
            sourceConnectionId: new byte[sourceConnectionIdLength]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
    }
}

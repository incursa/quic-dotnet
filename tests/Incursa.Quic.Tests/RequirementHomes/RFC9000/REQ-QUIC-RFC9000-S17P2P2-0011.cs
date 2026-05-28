// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_PreservesANonBoundarySourceConnectionId()
    {
        byte[] sourceConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(sourceConnectionId: sourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Edge)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    public void TryParseLongHeader_PreservesSourceConnectionIdRange(int sourceConnectionIdLength)
    {
        byte[] destinationConnectionId = [0xDA];
        byte[] sourceConnectionId = new byte[sourceConnectionIdLength];
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01],
            protectedPayload: [0xAA]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal(1, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    public void TryParseLongHeader_RejectsInitialSourceConnectionIdsLongerThan20Bytes()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0xDA],
            sourceConnectionId: new byte[21],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: [0xAA]));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }
}

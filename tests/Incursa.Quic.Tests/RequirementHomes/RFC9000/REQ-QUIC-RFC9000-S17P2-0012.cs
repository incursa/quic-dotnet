namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0012">Packets that use the long header MUST contain the following fields:</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0012")]
public sealed class REQ_QUIC_RFC9000_S17P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0012">Packets that use the long header MUST contain the following fields:</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0012")]
    public void TryParseLongHeader_ExposesTheRequiredFieldsOnVersion1InitialPackets()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xAA, 0xBB],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xCC, 0xDD]);

        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20, 0x21, 0x22],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x40, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.Equal((byte)0x00, header.TypeSpecificBits);
        Assert.Equal(1u, header.Version);
        Assert.False(header.IsVersionNegotiation);
        Assert.Equal(2, header.DestinationConnectionIdLength);
        Assert.True(new byte[] { 0x10, 0x11 }.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(3, header.SourceConnectionIdLength);
        Assert.True(new byte[] { 0x20, 0x21, 0x22 }.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0012">Packets that use the long header MUST contain the following fields:</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0012")]
    public void TryParseLongHeader_ExposesTheRequiredFieldsOnVersionNegotiationPackets()
    {
        byte[] supportedVersions = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x5A,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22, 0x23],
            supportedVersions: [0x01020304u, 0x05060708u]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x5A, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x01, header.LongPacketTypeBits);
        Assert.Equal((byte)0x0A, header.TypeSpecificBits);
        Assert.Equal(0u, header.Version);
        Assert.True(header.IsVersionNegotiation);
        Assert.Equal(1, header.DestinationConnectionIdLength);
        Assert.True(new byte[] { 0x11 }.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(2, header.SourceConnectionIdLength);
        Assert.True(new byte[] { 0x22, 0x23 }.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(supportedVersions.AsSpan().SequenceEqual(header.VersionSpecificData));
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0018">The byte following the version MUST contain the length in bytes of the Destination Connection ID field that follows it.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0018")]
public sealed class REQ_QUIC_RFC9000_S17P2_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0018">The byte following the version MUST contain the length in bytes of the Destination Connection ID field that follows it.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0018")]
    public void TryParseVersionNegotiation_PreservesARepresentativeDestinationConnectionIdLengthByte()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            supportedVersions: 0x01020304);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(1, header.DestinationConnectionIdLength);
        Assert.Equal(1, header.DestinationConnectionId.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(255)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0018">The byte following the version MUST contain the length in bytes of the Destination Connection ID field that follows it.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0018")]
    public void TryParseVersionNegotiation_PreservesBoundaryDestinationConnectionIdLengthBytes(
        int destinationConnectionIdLength)
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: new byte[destinationConnectionIdLength],
            sourceConnectionId: [0x22],
            supportedVersions: 0x01020304);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionIdLength);
        Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionId.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0018">The byte following the version MUST contain the length in bytes of the Destination Connection ID field that follows it.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0018")]
    public void TryParseVersionNegotiation_RejectsPacketsMissingTheDestinationConnectionIdLengthField()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            supportedVersions: 0x01020304);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet[..5], out _));
    }
}

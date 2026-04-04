namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0009">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0009")]
public sealed class REQ_QUIC_RFC9000_S17P2_0009
{
    [Theory]
    [InlineData(1)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0009">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0009")]
    public void TryParseLongHeader_PreservesTheSourceConnectionIdLengthInVersion1Packets(
        int sourceConnectionIdLength)
    {
        byte[] sourceConnectionId = new byte[sourceConnectionIdLength];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId,
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [0xAA],
                packetNumber: [0x01],
                protectedPayload: [0xBB]));

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0009">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0009")]
    public void TryParseLongHeader_RejectsVersion1SourceConnectionIdsLongerThan20Bytes()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: Enumerable.Repeat((byte)0x5C, 21).ToArray(),
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [0xAA],
                packetNumber: [0x01],
                protectedPayload: [0xBB]));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }
}

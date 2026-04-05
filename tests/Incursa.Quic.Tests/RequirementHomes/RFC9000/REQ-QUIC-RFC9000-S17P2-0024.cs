namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0024">The byte following the Destination Connection ID MUST contain the length in bytes of the Source Connection ID field that follows it.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0024")]
public sealed class REQ_QUIC_RFC9000_S17P2_0024
{
    [Theory]
    [InlineData(0, 1)]
    [InlineData(3, 2)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0024">The byte following the Destination Connection ID MUST contain the length in bytes of the Source Connection ID field that follows it.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0024")]
    public void TryParseLongHeader_ExposesTheSourceConnectionIdLengthByteAfterTheDestinationConnectionId(
        int destinationConnectionIdLength,
        int sourceConnectionIdLength)
    {
        byte[] destinationConnectionId = Enumerable.Repeat((byte)0xDA, destinationConnectionIdLength).ToArray();
        byte[] sourceConnectionId = Enumerable.Repeat((byte)0x5C, sourceConnectionIdLength).ToArray();
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xAA],
            packetNumber: [0x01],
            protectedPayload: [0xBB]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)destinationConnectionIdLength, packet[5]);
        Assert.Equal((byte)sourceConnectionIdLength, packet[6 + destinationConnectionIdLength]);
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0024">The byte following the Destination Connection ID MUST contain the length in bytes of the Source Connection ID field that follows it.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0024")]
    public void TryParseLongHeader_RejectsPacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10, 0x11, 0x12],
            sourceConnectionId: [0x20, 0x21],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [0xAA],
                packetNumber: [0x01],
                protectedPayload: [0xBB]));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..9], out _));
    }
}

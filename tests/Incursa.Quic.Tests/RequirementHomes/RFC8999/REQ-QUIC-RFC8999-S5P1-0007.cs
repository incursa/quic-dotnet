namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0007">The Source Connection ID field MUST follow its length byte and be between 0 and 255 bytes long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC8999-S5P1-0007")]
public sealed class REQ_QUIC_RFC8999_S5P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0007">The Source Connection ID field MUST follow its length byte and be between 0 and 255 bytes long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0007")]
    public void TryParseLongHeader_AcceptsMaximumLengthSourceConnectionId()
    {
        byte[] sourceConnectionId = Enumerable.Repeat((byte)0x5C, byte.MaxValue).ToArray();
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 0x11223344,
            destinationConnectionId: [0xDA],
            sourceConnectionId,
            versionSpecificData: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(byte.MaxValue, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0007">The Source Connection ID field MUST follow its length byte and be between 0 and 255 bytes long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0007")]
    public void TryParseLongHeader_RejectsTruncatedSourceConnectionId()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 0x11223344,
            destinationConnectionId: [0xDA],
            sourceConnectionId: [0x5C, 0x5D, 0x5E],
            versionSpecificData: []);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..^1], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0007">The Source Connection ID field MUST follow its length byte and be between 0 and 255 bytes long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0007")]
    public void TryParseLongHeader_AllowsZeroLengthSourceConnectionId()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 0x11223344,
            destinationConnectionId: [0xDA],
            sourceConnectionId: [],
            versionSpecificData: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(header.SourceConnectionId.IsEmpty);
    }
}

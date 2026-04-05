namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0008">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0008")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0008">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0008")]
    public void TryParseLongHeader_PreservesTheDestinationConnectionIdLengthByte()
    {
        byte[] destinationConnectionId = [0x10];
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: destinationConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(1, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0008">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0008")]
    public void TryParseLongHeader_RejectsPacketsMissingTheDestinationConnectionIdLengthByte()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..5], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0008">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0008")]
    public void TryParseLongHeader_AllowsZeroLengthDestinationConnectionIds()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: [0x20]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.DestinationConnectionIdLength);
        Assert.True(header.DestinationConnectionId.IsEmpty);
    }
}

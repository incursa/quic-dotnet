namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0010")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0010")]
    public void TryParseLongHeader_PreservesTheSourceConnectionIdLengthByte()
    {
        byte[] sourceConnectionId = [0x20];
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            sourceConnectionId: sourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(1, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0010")]
    public void TryParseLongHeader_RejectsPacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..7], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0010")]
    public void TryParseLongHeader_AllowsZeroLengthSourceConnectionIds()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [0x10],
            sourceConnectionId: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(header.SourceConnectionId.IsEmpty);
    }
}

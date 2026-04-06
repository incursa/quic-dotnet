namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0007">The client MUST populate the Source Connection ID field with a value of its choosing and set the Source Connection ID Length field to indicate the length.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S7P2-0007")]
public sealed class REQ_QUIC_RFC9000_S7P2_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0007">The client MUST populate the Source Connection ID field with a value of its choosing and set the Source Connection ID Length field to indicate the length.</workbench-requirement>
    /// </workbench-requirements>
    public void TryParseLongHeader_ExposesTheChosenHandshakeSourceConnectionId()
    {
        byte[] sourceConnectionId = [0x20, 0x21, 0x22];
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: [0x10, 0x11, 0x12],
            sourceConnectionId: sourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0007">The client MUST populate the Source Connection ID field with a value of its choosing and set the Source Connection ID Length field to indicate the length.</workbench-requirement>
    /// </workbench-requirements>
    public void TryParseLongHeader_RejectsHandshakePacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20, 0x21]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..8], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0007">The client MUST populate the Source Connection ID field with a value of its choosing and set the Source Connection ID Length field to indicate the length.</workbench-requirement>
    /// </workbench-requirements>
    public void TryParseLongHeader_AllowsAZeroLengthHandshakeSourceConnectionId()
    {
        byte[] destinationConnectionId = [0x10];
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(header.SourceConnectionId.IsEmpty);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
    }
}

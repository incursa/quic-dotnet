namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0002">Connection IDs MUST be independently selected by endpoints, with each endpoint selecting the connection IDs that its peer uses.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1-0002")]
public sealed class REQ_QUIC_RFC9000_S5P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0002">Connection IDs MUST be independently selected by endpoints, with each endpoint selecting the connection IDs that its peer uses.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0002")]
    public void TryParseLongHeader_ExposesTheHandshakeConnectionIds()
    {
        byte[] destinationConnectionId = [0x10, 0x11, 0x12];
        byte[] sourceConnectionId = [0x20, 0x21];
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: sourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }
}

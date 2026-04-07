namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1-0007")]
public sealed class REQ_QUIC_RFC9000_S5P1_0007
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0007">The Source Connection ID field MUST follow its length byte and be between 0 and 255 bytes long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AllowsMaximumLengthSourceConnectionIds()
    {
        byte[] destinationConnectionId = [0xDA];
        byte[] sourceConnectionId = new byte[byte.MaxValue];
        byte[] versionSpecificData = [0x10, 0x20, 0x30];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 0x11223344,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(byte.MaxValue, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }
}

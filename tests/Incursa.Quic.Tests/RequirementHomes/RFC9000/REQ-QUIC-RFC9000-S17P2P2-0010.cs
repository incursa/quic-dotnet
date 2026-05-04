namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_PreservesTheSourceConnectionIdLengthByte()
    {
        byte[] sourceConnectionId = [0x20, 0x21, 0x22];
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(sourceConnectionId: sourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsPacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHeaderTestData.BuildTruncatedLongHeader(
            headerControlBits: 0x52,
            version: 0x01020304,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21, 0x22],
            versionSpecificData: [],
            truncateBy: 3);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsSourceConnectionIdLengthByteBoundaries(int sourceConnectionIdLength)
    {
        byte[] sourceConnectionId = new byte[sourceConnectionIdLength];
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(sourceConnectionId: sourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
    }
}

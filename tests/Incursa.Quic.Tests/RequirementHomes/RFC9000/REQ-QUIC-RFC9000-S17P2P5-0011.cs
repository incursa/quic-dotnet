namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0011")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0011")]
    public void TryParseLongHeader_AllowsSourceConnectionIdsUpTo20Bytes()
    {
        byte[] sourceConnectionId = Enumerable.Repeat((byte)0x5C, 20).ToArray();
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            sourceConnectionId: sourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(20, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0011")]
    public void TryParseLongHeader_RejectsSourceConnectionIdsLongerThan20Bytes()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            sourceConnectionId: Enumerable.Repeat((byte)0x5C, 21).ToArray());

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0011")]
    public void TryParseLongHeader_AllowsZeroLengthSourceConnectionIds()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(sourceConnectionId: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(header.SourceConnectionId.IsEmpty);
    }
}

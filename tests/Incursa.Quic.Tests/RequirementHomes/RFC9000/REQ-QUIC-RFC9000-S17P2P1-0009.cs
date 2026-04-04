namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0009">The Source Connection ID field MUST be between 0 and 2040 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0009")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0009
{
    [Theory]
    [InlineData(0)]
    [InlineData(255)]
    [CoverageType(RequirementCoverageType.Edge)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0009">The Source Connection ID field MUST be between 0 and 2040 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0009")]
    public void TryParseVersionNegotiation_PreservesSourceConnectionIdRange(int sourceConnectionIdLength)
    {
        byte[] sourceConnectionId = new byte[sourceConnectionIdLength];
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x11],
            sourceConnectionId: sourceConnectionId,
            supportedVersions: 0x01020304);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0009">The Source Connection ID field MUST be between 0 and 2040 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0009")]
    public void TryParseVersionNegotiation_RejectsTruncatedSourceConnectionId()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            supportedVersions: 0x01020304);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet[..8], out _));
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0022">In order to properly form a Version Negotiation packet, servers SHOULD be able to read longer connection IDs from other QUIC versions.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0022")]
public sealed class REQ_QUIC_RFC9000_S17P2_0022
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0022">In order to properly form a Version Negotiation packet, servers SHOULD be able to read longer connection IDs from other QUIC versions.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0022")]
    public void TryParseVersionNegotiation_ReadsLongerConnectionIdsFromOtherVersions()
    {
        byte[] destinationConnectionId = Enumerable.Repeat((byte)0xD1, 255).ToArray();
        byte[] sourceConnectionId = Enumerable.Repeat((byte)0x51, 255).ToArray();
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4E,
            destinationConnectionId,
            sourceConnectionId,
            0x01020304,
            0x11223344);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(255, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(255, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.Equal(2, header.SupportedVersionCount);
    }
}

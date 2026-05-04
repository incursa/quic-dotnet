namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0015">The Initial packet MUST contain a long header as well as the Length and Packet Number fields; see Section 17.2.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0015")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketLength_AccountsForTheInitialLengthAndPacketNumberFields()
    {
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(
            packetNumberLength: 3,
            protectedPayload: [0xB0, 0xB1]);

        Assert.True(QuicPacketParser.TryGetPacketLength(packet, out int packetLength));
        Assert.Equal(packet.Length, packetLength);
        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0015">The Initial packet MUST contain a long header as well as the Length and Packet Number fields; see Section 17.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsInitialPacketsMissingLengthAndPacketNumberFields()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: []);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryGetPacketLength_AcceptsTheMinimalInitialLengthAndPacketNumberFields()
    {
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket(
            packetNumberLength: 1,
            token: [],
            protectedPayload: []);

        Assert.True(QuicPacketParser.TryGetPacketLength(packet, out int packetLength));
        Assert.Equal(packet.Length, packetLength);
    }
}

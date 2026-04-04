namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P3-0001">A Retry packet MUST NOT be treated as an acknowledgment.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P3-0001")]
public sealed class REQ_QUIC_RFC9002_S6P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetPacketNumberSpace_MapsInitialPacketsToTheInitialSpace()
    {
        byte[] initialPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([0xAA], [0x01], [0xBB]));

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGetPacketNumberSpace_RejectsRetryPackets()
    {
        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x70,
            version: 1,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: [0x33]);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }
}

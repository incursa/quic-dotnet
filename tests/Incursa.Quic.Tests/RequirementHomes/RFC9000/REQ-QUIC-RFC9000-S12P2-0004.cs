namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P2-0004">Receivers MUST be able to process coalesced packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P2-0004")]
public sealed class REQ_QUIC_RFC9000_S12P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AllowsReceiversToProcessTwoLengthDelimitedPacketsInTheSameDatagram()
    {
        byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xA0],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0]);
        byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            firstVersionSpecificData);
        byte[] secondVersionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x03, 0x04],
            protectedPayload: [0xC0]);
        byte[] secondPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x62,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            secondVersionSpecificData);
        byte[] datagram = [.. firstPacket, .. secondPacket];

        Assert.Equal(firstPacket.Length + secondPacket.Length, datagram.Length);
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram[..firstPacket.Length], out QuicLongHeaderPacket firstHeader));
        Assert.Equal(firstPacket.Length, 1 + 4 + 1 + firstHeader.DestinationConnectionIdLength + 1 + firstHeader.SourceConnectionIdLength + firstHeader.VersionSpecificData.Length);
        Assert.True(firstVersionSpecificData.AsSpan().SequenceEqual(firstHeader.VersionSpecificData));
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram.AsSpan(firstPacket.Length), out QuicLongHeaderPacket secondHeader));
        Assert.Equal((byte)0x02, secondHeader.LongPacketTypeBits);
        Assert.True(secondVersionSpecificData.AsSpan().SequenceEqual(secondHeader.VersionSpecificData));
    }
}

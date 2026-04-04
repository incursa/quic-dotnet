namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0031">In packet types that MUST contain a Packet Number field, the least significant two bits (those with a mask of 0x03) of byte 0 contain the length of the Packet Number field, encoded as an unsigned two-bit integer that is one less than the length of the Packet Number field in bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0031")]
public sealed class REQ_QUIC_RFC9000_S17P2_0031
{
    public static TheoryData<int> InteriorPacketNumberLengthCases => new()
    {
        { 2 },
        { 3 },
    };

    [Theory]
    [MemberData(nameof(InteriorPacketNumberLengthCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_ExposesThePacketNumberLengthBitsForInteriorPacketNumberLengths(int packetNumberLength)
    {
        (byte[] packet, byte[] versionSpecificData) = BuildInitialPacket(packetNumberLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsPacketsWhenThePayloadIsShorterThanThePacketNumberField()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x43,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x00, 0x03, 0x01, 0x02, 0x03, 0x04]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseLongHeader_AllowsTheShortestAndLongestPacketNumberLengths(int packetNumberLength)
    {
        (byte[] packet, byte[] versionSpecificData) = BuildInitialPacket(packetNumberLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    private static (byte[] Packet, byte[] VersionSpecificData) BuildInitialPacket(int packetNumberLength)
    {
        byte[] packetNumber = CreatePacketNumber(packetNumberLength);
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xAA],
            packetNumber,
            protectedPayload: [0xBB]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(0x40 | (packetNumberLength - 1)),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData);
        return (packet, versionSpecificData);
    }

    private static byte[] CreatePacketNumber(int packetNumberLength)
    {
        return Enumerable.Range(0, packetNumberLength)
            .Select(index => (byte)(index + 1))
            .ToArray();
    }
}

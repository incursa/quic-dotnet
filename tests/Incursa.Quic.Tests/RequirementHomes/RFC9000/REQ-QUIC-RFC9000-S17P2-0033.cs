namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0033">The length of the Packet Number field MUST be encoded in the Packet Number Length bits of byte 0; see above.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0033")]
public sealed class REQ_QUIC_RFC9000_S17P2_0033
{
    public static TheoryData<int> BoundaryPacketNumberLengthCases => new()
    {
        { 1 },
        { 4 },
    };

    [Theory]
    [MemberData(nameof(BoundaryPacketNumberLengthCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseLongHeader_EncodesThePacketNumberLengthBitsInZeroRttHeaders(int packetNumberLength)
    {
        (byte[] packet, byte[] versionSpecificData) = BuildZeroRttPacket(packetNumberLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x01, header.LongPacketTypeBits);
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsZeroRttPacketsWhenThePayloadIsShorterThanThePacketNumberField()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x53,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x03, 0x01, 0x02, 0x03, 0x04]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    private static (byte[] Packet, byte[] VersionSpecificData) BuildZeroRttPacket(int packetNumberLength)
    {
        byte[] packetNumber = CreatePacketNumber(packetNumberLength);
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber,
            protectedPayload: [0xBB]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(0x50 | (packetNumberLength - 1)),
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

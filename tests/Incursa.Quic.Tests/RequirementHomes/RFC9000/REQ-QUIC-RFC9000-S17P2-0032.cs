namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0032">The Packet Number field MUST be field is 1 to 4 bytes long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0032")]
public sealed class REQ_QUIC_RFC9000_S17P2_0032
{
    public static TheoryData<int> PacketNumberLengthCases => new()
    {
        { 1 },
        { 2 },
        { 3 },
        { 4 },
    };

    [Theory]
    [MemberData(nameof(PacketNumberLengthCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AllowsZeroRttPacketNumbersFromOneToFourBytes(int packetNumberLength)
    {
        (byte[] packet, byte[] versionSpecificData) = BuildZeroRttPacket(packetNumberLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x01, header.LongPacketTypeBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
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

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0010">Long headers MUST be used for packets that are sent prior to the establishment of 1-RTT keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0010")]
public sealed class REQ_QUIC_RFC9000_S17P2_0010
{
    [Theory]
    [InlineData((byte)0x00, 0)]
    [InlineData((byte)0x02, 1)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0010">Long headers MUST be used for packets that are sent prior to the establishment of 1-RTT keys.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0010")]
    public void TryParseLongHeader_MapsPre1RttPacketsToLongHeaderSpaces(
        byte longPacketTypeBits,
        int expectedPacketNumberSpaceValue)
    {
        QuicPacketNumberSpace expectedPacketNumberSpace = (QuicPacketNumberSpace)expectedPacketNumberSpaceValue;

        byte[] packet = BuildVersion1LongHeader(longPacketTypeBits);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal(longPacketTypeBits, header.LongPacketTypeBits);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(expectedPacketNumberSpace, packetNumberSpace);
    }

    private static byte[] BuildVersion1LongHeader(byte longPacketTypeBits)
    {
        byte headerControlBits = (byte)(0x40 | (longPacketTypeBits << 4));
        ReadOnlySpan<byte> versionSpecificData = longPacketTypeBits switch
        {
            0x00 => QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: [0xAA]),
            0x02 => QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                packetNumber: [0x01],
                protectedPayload: [0xAA]),
            _ => throw new ArgumentOutOfRangeException(nameof(longPacketTypeBits)),
        };

        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData);
    }
}

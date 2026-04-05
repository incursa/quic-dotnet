namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0011">Once 1-RTT keys are available, a sender MUST switch to sending packets using the short header (Section 17.3).</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0011")]
public sealed class REQ_QUIC_RFC9000_S17P2_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0011">Once 1-RTT keys are available, a sender MUST switch to sending packets using the short header (Section 17.3).</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0011")]
    public void TryParseShortHeader_RecognizesApplicationDataPackets()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0011">Once 1-RTT keys are available, a sender MUST switch to sending packets using the short header (Section 17.3).</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0011")]
    public void TryParseShortHeader_RejectsVersion1LongHeaders()
    {
        byte[] packet = BuildVersion1LongHeader(0x00);

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0011">Once 1-RTT keys are available, a sender MUST switch to sending packets using the short header (Section 17.3).</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0011")]
    public void TryParseShortHeader_AcceptsTheShortestValidShortHeader()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, []);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
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

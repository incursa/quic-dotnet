namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0009">Packets with short headers MUST include only the Destination Connection ID and omit the explicit length.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1-0009")]
public sealed class REQ_QUIC_RFC9000_S5P1_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_PreservesTrailingBytesWithoutAnExplicitLengthField()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);
        byte[] expectedRemainder = [0xAA, 0xBB, 0xCC];

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal((byte)0x24, header.HeaderControlBits);
        Assert.Equal(3, header.Remainder.Length);
        Assert.True(expectedRemainder.AsSpan().SequenceEqual(header.Remainder));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RejectsLongHeaderPackets()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30, 0x31]);

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseShortHeader_AcceptsTheShortestValidShortHeader()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, []);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Empty(header.Remainder);
    }
}

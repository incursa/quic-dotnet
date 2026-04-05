namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0026">While type-specific semantics for this version are described in the following sections, several long header packets in this version of QUIC MUST contain these additional fields:</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0026")]
public sealed class REQ_QUIC_RFC9000_S17P2_0026
{
    [Theory]
    [InlineData(0x40)]
    [InlineData(0x50)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0026">While type-specific semantics for this version are described in the following sections, several long header packets in this version of QUIC MUST contain these additional fields:</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0026")]
    public void TryParseLongHeader_PreservesVersion1LongHeaderVersionSpecificData(byte headerControlBits)
    {
        byte[] versionSpecificData = BuildVersion1VersionSpecificData(headerControlBits);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
        Assert.Equal((byte)((headerControlBits & 0x03)), header.PacketNumberLengthBits);
    }

    private static byte[] BuildVersion1VersionSpecificData(byte headerControlBits)
    {
        int packetNumberLength = (headerControlBits & 0x03) + 1;
        byte[] packetNumber = Enumerable.Range(0, packetNumberLength).Select(index => (byte)(index + 1)).ToArray();
        byte[] protectedPayload = [0xAA];
        return (headerControlBits & 0x30) == 0x10
            ? QuicHeaderTestData.BuildZeroRttVersionSpecificData(packetNumber, protectedPayload)
            : QuicHeaderTestData.BuildInitialVersionSpecificData([0xAA], packetNumber, protectedPayload);
    }
}

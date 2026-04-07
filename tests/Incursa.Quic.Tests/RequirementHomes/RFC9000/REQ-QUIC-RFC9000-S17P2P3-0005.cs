namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0005
{
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x3F)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0005">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsShortHeaderForm(byte headerControlBits)
    {
        byte[] shortHeader = QuicHeaderTestData.BuildShortHeader(
            headerControlBits,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        Assert.False(QuicPacketParser.TryParseLongHeader(shortHeader, out _));
    }
}

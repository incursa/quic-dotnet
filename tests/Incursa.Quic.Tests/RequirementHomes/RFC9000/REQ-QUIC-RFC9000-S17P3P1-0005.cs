namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0005">The Spin Bit field MUST be 1 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P3P1-0005")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_ReportsTheSpinBit()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x20, [0xA1, 0xB2]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(header.SpinBit);
    }
}

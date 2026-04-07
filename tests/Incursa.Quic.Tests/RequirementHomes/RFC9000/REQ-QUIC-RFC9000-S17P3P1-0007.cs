namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0007">The Key Phase field MUST be 1 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P3P1-0007")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_ReportsTheKeyPhaseBit()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x04, [0xA1, 0xB2]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(header.KeyPhase);
    }
}

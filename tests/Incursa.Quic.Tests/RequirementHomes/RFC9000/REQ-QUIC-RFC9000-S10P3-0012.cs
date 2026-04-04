namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0012">Endpoints MUST discard packets that are too small to be valid QUIC packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0012")]
public sealed class REQ_QUIC_RFC9000_S10P3_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseShortHeader_AcceptsAValidShortHeaderPacket()
    {
        byte[] remainder = [0xAA, 0xBB];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x24,
            remainder: remainder);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket parsed));
        Assert.Equal(QuicHeaderForm.Short, parsed.HeaderForm);
        Assert.Equal((byte)0x64, parsed.HeaderControlBits);
        Assert.True(parsed.Remainder.SequenceEqual(remainder));
    }
}

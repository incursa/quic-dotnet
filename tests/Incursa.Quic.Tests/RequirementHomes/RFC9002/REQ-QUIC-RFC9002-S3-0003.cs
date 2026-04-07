namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0003">The packet-level header MUST include a packet sequence number.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0003")]
public sealed class REQ_QUIC_RFC9002_S3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_PreservesThePacketSequenceNumberBytes()
    {
        byte[] remainder = [0xA1, 0xB2, 0xC3];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x03, remainder);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(packet.AsSpan(1).SequenceEqual(header.Remainder));
        Assert.Equal(remainder.Length, header.Remainder.Length);
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0005">The Long Packet Type field MUST be 2 bits long with value 3.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0005")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0005">The Long Packet Type field MUST be 2 bits long with value 3.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0005")]
    public void TryParseLongHeader_ExposesRetryLongPacketTypeThree()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x03, header.LongPacketTypeBits);
    }
}

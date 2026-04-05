namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0003">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0003")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0003">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0003")]
    public void TryParseLongHeader_ExposesTheRetryHeaderForm()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0001">As shown in Figure 18, a Retry packet MUST use a long packet header with a type value of 0x03.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0001")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0001">As shown in Figure 18, a Retry packet MUST use a long packet header with a type value of 0x03.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0001")]
    public void TryParseLongHeader_RecognizesRetryPacketsAsLongHeadersWithTypeThree()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x03, header.LongPacketTypeBits);
    }
}

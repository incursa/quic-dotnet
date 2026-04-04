namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0004">The encryption level MUST indicate the packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0004")]
public sealed class REQ_QUIC_RFC9002_S3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0004">The encryption level MUST indicate the packet number space.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    public void TryGetPacketNumberSpace_AcceptsTheShortestValidShortHeader()
    {
        byte[] packet = [0x40];

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
    }
}

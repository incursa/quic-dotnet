namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP2-0001">kPacketThreshold SHOULD be 3.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP2-0001")]
public sealed class REQ_QUIC_RFC9002_SAP2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecommendedPacketThreshold_UsesThreePackets()
    {
        Assert.Equal(3, QuicRecoveryTiming.RecommendedPacketThreshold);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldDeclarePacketLostByPacketThreshold_RejectsThresholdsBelowThree()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
                packetNumber: 8,
                largestAcknowledgedPacketNumber: 11,
                packetThreshold: 2));

        Assert.Equal("packetThreshold", exception.ParamName);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ShouldDeclarePacketLostByPacketThreshold_UsesTheThreePacketBoundary()
    {
        Assert.True(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 0,
            largestAcknowledgedPacketNumber: 3));
    }
}

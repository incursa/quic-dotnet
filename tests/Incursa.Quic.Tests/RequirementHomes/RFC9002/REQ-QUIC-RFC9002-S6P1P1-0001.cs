namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P1-0001">The packet reordering threshold SHOULD be 3.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P1P1-0001")]
public sealed class REQ_QUIC_RFC9002_S6P1P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldDeclarePacketLostByPacketThreshold_DeclaresPacketsOlderThanTheRecommendedThreshold()
    {
        Assert.True(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 6,
            largestAcknowledgedPacketNumber: 10));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ShouldDeclarePacketLostByPacketThreshold_DoesNotUseAThresholdAboveThreeAtTheBoundary()
    {
        Assert.False(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 0,
            largestAcknowledgedPacketNumber: QuicRecoveryTiming.RecommendedPacketThreshold,
            packetThreshold: QuicRecoveryTiming.RecommendedPacketThreshold + 1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ShouldDeclarePacketLostByPacketThreshold_UsesTheThreePacketBoundary()
    {
        Assert.True(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 0,
            largestAcknowledgedPacketNumber: QuicRecoveryTiming.RecommendedPacketThreshold,
            packetThreshold: QuicRecoveryTiming.RecommendedPacketThreshold));
    }
}

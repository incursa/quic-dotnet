namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P1-0002">Implementations SHOULD NOT use a packet threshold less than 3.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P1P1-0002")]
public sealed class REQ_QUIC_RFC9002_S6P1P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ShouldDeclarePacketLostByPacketThreshold_UsesTheMinimumRecommendedThreshold()
    {
        Assert.True(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 0,
            largestAcknowledgedPacketNumber: QuicRecoveryTiming.RecommendedPacketThreshold,
            packetThreshold: QuicRecoveryTiming.RecommendedPacketThreshold));
    }
}

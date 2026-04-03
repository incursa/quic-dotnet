namespace Incursa.Quic.Tests;

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

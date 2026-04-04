namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP1-0002")]
public sealed class REQ_QUIC_RFC9002_SBP1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryComputePersistentCongestionDurationMicros_UsesTheRecommendedPersistentCongestionThreshold()
    {
        Assert.Equal(3, QuicCongestionControlState.RecommendedPersistentCongestionThreshold);

        Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            persistentCongestionDurationMicros: out ulong durationMicros,
            persistentCongestionThreshold: QuicCongestionControlState.RecommendedPersistentCongestionThreshold,
            timerGranularityMicros: 1_000));

        Assert.Equal(6_000UL, durationMicros);
    }
}

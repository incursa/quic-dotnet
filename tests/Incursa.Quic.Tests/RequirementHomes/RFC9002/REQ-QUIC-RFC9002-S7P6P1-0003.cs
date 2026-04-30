namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P6P1-0003")]
public sealed class REQ_QUIC_RFC9002_S7P6P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecommendedPersistentCongestionThresholdIsThree()
    {
        Assert.Equal(3, QuicCongestionControlState.RecommendedPersistentCongestionThreshold);
        Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out ulong durationMicros,
            persistentCongestionThreshold: QuicCongestionControlState.RecommendedPersistentCongestionThreshold));

        Assert.Equal(6_000UL, durationMicros);
    }
}

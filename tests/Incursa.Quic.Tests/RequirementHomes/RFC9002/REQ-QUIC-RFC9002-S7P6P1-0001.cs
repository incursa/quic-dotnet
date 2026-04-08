namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P6P1-0001")]
public sealed class REQ_QUIC_RFC9002_S7P6P1_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P6-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryComputePersistentCongestionDurationMicros_UsesTheExpectedFormulaAndReductionHelper()
    {
        Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out ulong durationMicros));
        Assert.Equal(6_000UL, durationMicros);

        Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros: 1_000,
            rttVarMicros: 400,
            maxAckDelayMicros: 500,
            out ulong adjustedDurationMicros));
        Assert.Equal(9_300UL, adjustedDurationMicros);

        Assert.Equal(9_000UL, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
            12_000,
            reductionNumerator: 3,
            reductionDenominator: 4,
            minimumCongestionWindowBytes: 2_400));

        Assert.Equal(2_400UL, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
            1_000,
            reductionNumerator: 3,
            reductionDenominator: 4,
            minimumCongestionWindowBytes: 2_400));
    }
}

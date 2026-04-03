namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P1-0001")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0001
{
    public static TheoryData<VarianceBoundaryCase> VarianceBoundaryCases => new()
    {
        new(62, 1_752),
        new(63, 1_752),
        new(64, 1_756),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeProbeTimeoutMicros_RejectsAZeroTimerGranularity()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
                QuicPacketNumberSpace.ApplicationData,
                smoothedRttMicros: 1_000,
                rttVarMicros: 250,
                maxAckDelayMicros: 500,
                handshakeConfirmed: true,
                out _,
                timerGranularityMicros: 0));

        Assert.Equal("timerGranularityMicros", exception.ParamName);
    }

    [Theory]
    [MemberData(nameof(VarianceBoundaryCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeProbeTimeoutMicros_ClampsTheVarianceComponentAtTheGranularityBoundary(VarianceBoundaryCase scenario)
    {
        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.ApplicationData,
            smoothedRttMicros: 1_000,
            rttVarMicros: scenario.RttVarMicros,
            maxAckDelayMicros: 500,
            handshakeConfirmed: true,
            out ulong probeTimeoutMicros,
            timerGranularityMicros: 252));

        Assert.Equal(scenario.ExpectedProbeTimeoutMicros, probeTimeoutMicros);
    }

    public sealed record VarianceBoundaryCase(
        ulong RttVarMicros,
        ulong ExpectedProbeTimeoutMicros);
}

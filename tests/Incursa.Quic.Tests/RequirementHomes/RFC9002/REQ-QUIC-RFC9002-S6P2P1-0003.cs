namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P1-0003")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0003
{
    public static TheoryData<PtoGranularityFloorCase> PtoGranularityFloorCases => new()
    {
        new(62, 252),
        new(63, 252),
        new(64, 256),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeProbeTimeoutMicros_RejectsAZeroTimerGranularity()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
                QuicPacketNumberSpace.Initial,
                smoothedRttMicros: 0,
                rttVarMicros: 62,
                maxAckDelayMicros: 0,
                handshakeConfirmed: false,
                out _,
                timerGranularityMicros: 0));

        Assert.Equal("timerGranularityMicros", exception.ParamName);
    }

    [Theory]
    [MemberData(nameof(PtoGranularityFloorCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeProbeTimeoutMicros_ClampsThePtoPeriodToTheGranularityFloor(PtoGranularityFloorCase scenario)
    {
        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.Initial,
            smoothedRttMicros: 0,
            rttVarMicros: scenario.RttVarMicros,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false,
            out ulong probeTimeoutMicros,
            timerGranularityMicros: 252));

        Assert.Equal(scenario.ExpectedProbeTimeoutMicros, probeTimeoutMicros);
    }

    public sealed record PtoGranularityFloorCase(
        ulong RttVarMicros,
        ulong ExpectedProbeTimeoutMicros);
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P1-0007")]
public sealed class REQ_QUIC_RFC9000_S10P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeEffectiveIdleTimeoutMicros_RejectsAZeroProbeTimeout()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: null,
            peerMaxIdleTimeoutMicros: 18,
            currentProbeTimeoutMicros: 0,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryComputeEffectiveIdleTimeoutMicros_SaturatesThePtoFloorAtUlongMaxValue()
    {
        ulong currentProbeTimeoutMicros = (ulong.MaxValue / 3) + 1;

        Assert.True(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: 1,
            peerMaxIdleTimeoutMicros: null,
            currentProbeTimeoutMicros: currentProbeTimeoutMicros,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(ulong.MaxValue, effectiveIdleTimeoutMicros);
    }
}

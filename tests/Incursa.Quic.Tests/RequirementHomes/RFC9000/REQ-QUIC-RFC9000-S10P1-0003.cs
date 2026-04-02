namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S10P1_0003
{
    [Theory]
    [InlineData(25UL, null, 5UL, true, 25UL)]
    [InlineData(0UL, 40UL, 5UL, true, 40UL)]
    [InlineData(25UL, 40UL, 5UL, true, 25UL)]
    [InlineData(4UL, 10UL, 2UL, true, 6UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0007")]
    public void TryComputeEffectiveIdleTimeoutMicros_UsesTheMinimumAdvertisedValueAndThePtoFloor(
        ulong? localMaxIdleTimeoutMicros,
        ulong? peerMaxIdleTimeoutMicros,
        ulong currentProbeTimeoutMicros,
        bool expectedComputed,
        ulong expectedEffectiveIdleTimeoutMicros)
    {
        Assert.Equal(expectedComputed, QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros,
            peerMaxIdleTimeoutMicros,
            currentProbeTimeoutMicros,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(expectedEffectiveIdleTimeoutMicros, effectiveIdleTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    public void TryComputeEffectiveIdleTimeoutMicros_ReturnsFalseWhenNeitherEndpointAdvertisesAnIdleTimeout()
    {
        Assert.False(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: null,
            peerMaxIdleTimeoutMicros: null,
            currentProbeTimeoutMicros: 5,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(0UL, effectiveIdleTimeoutMicros);
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0003">Each endpoint MUST advertise a `max_idle_timeout`, and the effective value at an endpoint is the minimum of the two advertised values, or the sole advertised value if only one endpoint advertises a non-zero value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
public sealed class REQ_QUIC_RFC9000_S10P1_0003
{
    [Theory]
    [InlineData(25UL, null, 5UL, true, 25UL)]
    [InlineData(0UL, 40UL, 5UL, true, 40UL)]
    [InlineData(25UL, 40UL, 5UL, true, 25UL)]
    [InlineData(4UL, 10UL, 2UL, true, 6UL)]
    [CoverageType(RequirementCoverageType.Positive)]
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
    public void TryComputeEffectiveIdleTimeoutMicros_ReturnsFalseWhenNeitherEndpointAdvertisesAnIdleTimeout()
    {
        Assert.False(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: null,
            peerMaxIdleTimeoutMicros: null,
            currentProbeTimeoutMicros: 5,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(0UL, effectiveIdleTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryComputeEffectiveIdleTimeoutMicros_UsesTheOneMicrosecondBoundaryWhenOneEndpointIsDisabled()
    {
        Assert.True(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: 0,
            peerMaxIdleTimeoutMicros: 1,
            currentProbeTimeoutMicros: 1,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(3UL, effectiveIdleTimeoutMicros);
    }
}

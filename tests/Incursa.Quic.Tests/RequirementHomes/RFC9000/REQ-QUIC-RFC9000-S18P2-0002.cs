namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0002")]
public sealed class REQ_QUIC_RFC9000_S18P2_0002
{
    [Theory]
    [InlineData(0, 0UL)]
    [InlineData(1, 1UL)]
    [InlineData(30_000, 30_000UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IdleTimeoutToMaxIdleTimeoutMilliseconds_EncodesTheWireValueInMilliseconds(
        int milliseconds,
        ulong expectedMaxIdleTimeout)
    {
        Assert.Equal(
            expectedMaxIdleTimeout,
            QuicTransportParameterTimeUnits.IdleTimeoutToMaxIdleTimeoutMilliseconds(
                TimeSpan.FromMilliseconds(milliseconds)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void IdleTimeoutToMaxIdleTimeoutMilliseconds_RoundsSubMillisecondPositiveValuesUp()
    {
        Assert.Equal(
            1UL,
            QuicTransportParameterTimeUnits.IdleTimeoutToMaxIdleTimeoutMilliseconds(
                TimeSpan.FromTicks(1)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MaxIdleTimeoutMillisecondsToRuntimeMicros_ConvertsPeerWireValuesForTheRuntimeClock()
    {
        Assert.Equal(
            30_000_000UL,
            QuicTransportParameterTimeUnits.MaxIdleTimeoutMillisecondsToRuntimeMicros(30_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MaxIdleTimeoutMillisecondsToRuntimeMicros_PreservesAbsence()
    {
        Assert.Null(QuicTransportParameterTimeUnits.MaxIdleTimeoutMillisecondsToRuntimeMicros(null));
    }
}

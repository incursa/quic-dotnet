namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0007">When the RTT estimator is initialized, `smoothed_rtt` MUST be set to `kInitialRtt` and `rttvar` to `kInitialRtt / 2`.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P3-0007")]
public sealed class REQ_QUIC_RFC9002_S5P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void Constructor_InitializesSmoothedRttAndVariationFromTheConfiguredInitialRtt()
    {
        QuicRttEstimator estimator = new(initialRttMicros: 123_000);

        Assert.False(estimator.HasRttSample);
        Assert.Equal(123_000UL, estimator.InitialRttMicros);
        Assert.Equal(123_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(61_500UL, estimator.RttVarMicros);
    }
}

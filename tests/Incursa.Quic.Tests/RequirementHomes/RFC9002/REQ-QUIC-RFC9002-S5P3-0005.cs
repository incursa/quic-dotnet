namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0005">An endpoint MUST initialize the RTT estimator during connection establishment and when the estimator is reset during connection migration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P3-0005")]
public sealed class REQ_QUIC_RFC9002_S5P3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void Constructor_InitializesTheEstimatorAtConnectionStart()
    {
        QuicRttEstimator estimator = new();

        Assert.False(estimator.HasRttSample);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.InitialRttMicros);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, estimator.RttVarMicros);
    }
}

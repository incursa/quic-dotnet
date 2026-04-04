namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0005">The minimum congestion window SHOULD be 2 * max_datagram_size.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P2-0005")]
public sealed class REQ_QUIC_RFC9002_S7P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ComputeMinimumCongestionWindowBytes_UsesTwoDatagramsAtTheDefaultPathSize()
    {
        Assert.Equal(2_400UL, QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(1_200));
    }

    [Theory]
    [InlineData(1UL, 2UL)]
    [InlineData(ulong.MaxValue, ulong.MaxValue)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ComputeMinimumCongestionWindowBytes_ScalesAcrossBoundaryValues(
        ulong maxDatagramSizeBytes,
        ulong expectedMinimumCongestionWindowBytes)
    {
        Assert.Equal(expectedMinimumCongestionWindowBytes, QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(maxDatagramSizeBytes));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ComputeMinimumCongestionWindowBytes_RejectsZeroDatagramSizes()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(0));

        Assert.Equal("maxDatagramSizeBytes", exception.ParamName);
    }
}

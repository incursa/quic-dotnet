namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0003">If the maximum datagram size changes during the connection, the initial congestion window SHOULD be recalculated with the new size.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P2-0003")]
public sealed class REQ_QUIC_RFC9002_S7P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void UpdateMaxDatagramSize_RecomputesTheInitialWindowWhenTheDatagramSizeChanges()
    {
        QuicCongestionControlState state = new(1_200);
        state.RegisterPacketSent(1_200);

        state.UpdateMaxDatagramSize(1_500, resetToInitialWindow: true);

        Assert.Equal(1_500UL, state.MaxDatagramSizeBytes);
        Assert.Equal(14_720UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void UpdateMaxDatagramSize_DoesNotRecomputeTheWindowWhenResetIsFalse()
    {
        QuicCongestionControlState state = new(1_200);
        state.RegisterPacketSent(1_200);

        state.UpdateMaxDatagramSize(1_500, resetToInitialWindow: false);

        Assert.Equal(1_500UL, state.MaxDatagramSizeBytes);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.Equal(1_200UL, state.BytesInFlightBytes);
    }

    [Theory]
    [InlineData(1_472UL, 14_720UL)]
    [InlineData(7_361UL, 14_722UL)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void UpdateMaxDatagramSize_UsesTheTransitionPointForTheInitialWindow(
        ulong maxDatagramSizeBytes,
        ulong expectedInitialCongestionWindowBytes)
    {
        QuicCongestionControlState state = new(1_200);

        state.UpdateMaxDatagramSize(maxDatagramSizeBytes, resetToInitialWindow: true);

        Assert.Equal(maxDatagramSizeBytes, state.MaxDatagramSizeBytes);
        Assert.Equal(expectedInitialCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
    }
}

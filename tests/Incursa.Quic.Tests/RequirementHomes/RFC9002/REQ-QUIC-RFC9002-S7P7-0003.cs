namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0003">Senders SHOULD limit bursts to the initial congestion window.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P7-0003")]
public sealed class REQ_QUIC_RFC9002_S7P7_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetBurstLimitBytes_CapsTheBurstAtTheInitialCongestionWindow()
    {
        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: false,
            out ulong burstLimitBytes,
            largerBurstLimitBytes: 24_000));

        Assert.Equal(12_000UL, burstLimitBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetBurstLimitBytes_RejectsZeroInitialCongestionWindowBytes()
    {
        Assert.False(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 0,
            pathCanAbsorbLargerBursts: false,
            out ulong burstLimitBytes));

        Assert.Equal(0UL, burstLimitBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryGetBurstLimitBytes_PreservesTheInitialCongestionWindowWhenTheHigherLimitMatchesIt()
    {
        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: true,
            out ulong burstLimitBytes,
            largerBurstLimitBytes: 12_000));

        Assert.Equal(12_000UL, burstLimitBytes);
    }
}

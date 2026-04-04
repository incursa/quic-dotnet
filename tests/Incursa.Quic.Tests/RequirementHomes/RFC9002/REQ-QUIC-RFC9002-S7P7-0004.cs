namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0004">A sender with knowledge that the network path can absorb larger bursts MAY use a higher limit.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P7-0004")]
public sealed class REQ_QUIC_RFC9002_S7P7_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetBurstLimitBytes_UsesTheHigherLimitWhenThePathCanAbsorbLargerBursts()
    {
        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: true,
            out ulong burstLimitBytes,
            largerBurstLimitBytes: 24_000));

        Assert.Equal(24_000UL, burstLimitBytes);
    }
}

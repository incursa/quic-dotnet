namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0002">Senders MUST either use pacing or limit such bursts.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P7-0002")]
public sealed class REQ_QUIC_RFC9002_S7P7_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetBurstLimitBytes_ReturnsABurstCapWhenTheSenderDoesNotPace()
    {
        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: false,
            out ulong burstLimitBytes));

        Assert.Equal(12_000UL, burstLimitBytes);
    }
}

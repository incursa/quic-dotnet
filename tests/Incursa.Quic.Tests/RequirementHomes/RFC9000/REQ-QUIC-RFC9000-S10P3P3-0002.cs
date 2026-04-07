namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P3-0002">An endpoint MAY remember the number of Stateless Resets that it has sent and stop generating new Stateless Resets once a limit is reached.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P3-0002")]
public sealed class REQ_QUIC_RFC9000_S10P3P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSendStatelessReset_AllowsLoopPreventionState()
    {
        Assert.True(QuicStatelessReset.CanSendStatelessReset(100, 99, hasLoopPreventionState: false));
        Assert.False(QuicStatelessReset.CanSendStatelessReset(100, 300, hasLoopPreventionState: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanSendStatelessReset_RejectsLoopingViolations()
    {
        Assert.False(QuicStatelessReset.CanSendStatelessReset(100, 300, hasLoopPreventionState: true));
    }
}

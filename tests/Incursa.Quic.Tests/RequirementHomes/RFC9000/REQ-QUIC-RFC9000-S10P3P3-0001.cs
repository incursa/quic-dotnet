namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P3-0001">An endpoint MUST ensure that every Stateless Reset that it sends is smaller than the packet that triggered it, unless it maintains state sufficient to prevent looping.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P3-0001")]
public sealed class REQ_QUIC_RFC9000_S10P3P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSendStatelessReset_AllowsShorterResets()
    {
        Assert.True(QuicStatelessReset.CanSendStatelessReset(100, 99, hasLoopPreventionState: false));
        Assert.True(QuicStatelessReset.CanSendStatelessReset(100, 100, hasLoopPreventionState: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanSendStatelessReset_RejectsAmplificationViolations()
    {
        Assert.False(QuicStatelessReset.CanSendStatelessReset(100, 100, hasLoopPreventionState: false));
    }
}

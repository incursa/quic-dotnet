namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0028">An endpoint MUST NOT send a Stateless Reset that is three times or more larger than the packet it receives to avoid being used for amplification.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0028")]
public sealed class REQ_QUIC_RFC9000_S10P3_0028
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanSendStatelessReset_AllowsResponsesBelowTheThreeTimesAmplificationLimit()
    {
        Assert.True(QuicStatelessReset.CanSendStatelessReset(100, 299, hasLoopPreventionState: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void CanSendStatelessReset_RejectsResponsesAtTheThreeTimesAmplificationLimit()
    {
        Assert.False(QuicStatelessReset.CanSendStatelessReset(100, 300, hasLoopPreventionState: true));
    }
}

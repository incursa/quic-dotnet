namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2-0007">Endpoints MAY send a Stateless Reset for any packets that cannot be attributed to an existing connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P2-0007")]
public sealed class REQ_QUIC_RFC9000_S5P2_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSendStatelessReset_AllowsShorterResponsesForUnattributedPackets()
    {
        Assert.True(QuicStatelessReset.CanSendStatelessReset(100, 99, hasLoopPreventionState: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanSendStatelessReset_RejectsResponsesThatAreNotSmallerWithoutLoopPreventionState()
    {
        Assert.False(QuicStatelessReset.CanSendStatelessReset(100, 100, hasLoopPreventionState: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanSendStatelessReset_AllowsTheMinimumDatagramLengthWhenItIsStillSmallerThanTheTriggeringPacket()
    {
        Assert.True(QuicStatelessReset.CanSendStatelessReset(
            QuicStatelessReset.MinimumDatagramLength + 1,
            QuicStatelessReset.MinimumDatagramLength,
            hasLoopPreventionState: false));
    }
}

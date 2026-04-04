namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0002">If a max_idle_timeout is specified by either endpoint in its transport parameters, the connection MUST be silently closed and its state discarded when it remains idle for longer than the minimum of the max_idle_timeout values advertised by both endpoints.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P1-0002")]
public sealed class REQ_QUIC_RFC9000_S10P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HasTimedOut_ReturnsTrueAfterTheIdleDeadlinePasses()
    {
        QuicIdleTimeoutState state = new(100);
        state.RecordPeerPacketProcessed(20);

        Assert.False(state.HasTimedOut(120));
        Assert.True(state.HasTimedOut(121));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HasTimedOut_ReturnsFalseAtTheIdleDeadline()
    {
        QuicIdleTimeoutState state = new(100);

        Assert.False(state.HasTimedOut(100));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecordPeerPacketProcessed_SaturatesTheDeadlineAtUlongMaxValue()
    {
        QuicIdleTimeoutState state = new(ulong.MaxValue);

        state.RecordPeerPacketProcessed(1);

        Assert.Equal(1UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(ulong.MaxValue, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasTimedOut(ulong.MaxValue));
    }
}

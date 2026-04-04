namespace Incursa.Quic.Tests;

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

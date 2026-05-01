namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0079")]
public sealed class REQ_QUIC_CRT_0079
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LaterCloseAndResetEventsDoNotDowngradeDraining()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);

        QuicCrtLifecycleRequirementTestSupport.ReceivePeerClose(runtime, nowTicks: 1);
        QuicConnectionTerminalState firstTerminalState = runtime.TerminalState!.Value;
        long drainDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime)!.Value;

        QuicConnectionTransitionResult localCloseResult = QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(
            runtime,
            nowTicks: 2);
        QuicConnectionTransitionResult resetResult = QuicCrtLifecycleRequirementTestSupport.AcceptStatelessReset(
            runtime,
            nowTicks: 3);

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(firstTerminalState, runtime.TerminalState);
        Assert.Equal(drainDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
        Assert.False(localCloseResult.StateChanged);
        Assert.Empty(localCloseResult.Effects);
        Assert.False(resetResult.StateChanged);
        Assert.Empty(resetResult.Effects);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LaterCloseAndResetEventsDoNotReopenDiscarded()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);

        QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(runtime, nowTicks: 1);
        QuicCrtLifecycleRequirementTestSupport.ExpireCloseLifetime(runtime);
        QuicConnectionTerminalState discardedState = runtime.TerminalState!.Value;

        QuicConnectionTransitionResult localCloseResult = QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(
            runtime,
            nowTicks: 2);
        QuicConnectionTransitionResult peerCloseResult = QuicCrtLifecycleRequirementTestSupport.ReceivePeerClose(
            runtime,
            nowTicks: 3);
        QuicConnectionTransitionResult resetResult = QuicCrtLifecycleRequirementTestSupport.AcceptStatelessReset(
            runtime,
            nowTicks: 4);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(discardedState, runtime.TerminalState);
        Assert.False(localCloseResult.StateChanged);
        Assert.Empty(localCloseResult.Effects);
        Assert.False(peerCloseResult.StateChanged);
        Assert.Empty(peerCloseResult.Effects);
        Assert.False(resetResult.StateChanged);
        Assert.Empty(resetResult.Effects);
    }
}

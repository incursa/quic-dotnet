namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0077")]
public sealed class REQ_QUIC_CRT_0077
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedLocalCloseDoesNotReenterClosing()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);

        QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(runtime, nowTicks: 1);
        QuicConnectionTerminalState firstTerminalState = runtime.TerminalState!.Value;
        long closeDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;

        QuicConnectionTransitionResult result = QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(
            runtime,
            nowTicks: 2);

        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(firstTerminalState, runtime.TerminalState);
        Assert.Equal(closeDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime));
        Assert.False(result.StateChanged);
        Assert.Empty(result.Effects);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedPeerCloseDoesNotReenterDraining()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);

        QuicCrtLifecycleRequirementTestSupport.ReceivePeerClose(runtime, nowTicks: 1);
        QuicConnectionTerminalState firstTerminalState = runtime.TerminalState!.Value;
        long drainDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime)!.Value;

        QuicConnectionTransitionResult result = QuicCrtLifecycleRequirementTestSupport.ReceivePeerClose(
            runtime,
            nowTicks: 2);

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(firstTerminalState, runtime.TerminalState);
        Assert.Equal(drainDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
        Assert.False(result.StateChanged);
        Assert.Empty(result.Effects);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0053")]
public sealed class REQ_QUIC_CRT_0053
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SchedulerSuppressesStaleDueEntriesAfterATimerIsRearmed()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(11);

        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 10))
        {
            scheduler.Apply(handle, runtime, effect);
        }

        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 20))
        {
            scheduler.Apply(handle, runtime, effect);
        }

        Assert.False(scheduler.TryDequeueDueEntry(10, out _));
        Assert.True(scheduler.TryDequeueDueEntry(20, out QuicConnectionRuntimeScheduledTimerEntry currentEntry));
        Assert.Equal(QuicConnectionTimerKind.IdleTimeout, currentEntry.TimerKind);
        Assert.Equal(20L, currentEntry.DueTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RuntimeTreatsAStaleTimerExpiryGenerationAsANoOp()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionArmTimerEffect originalArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 10)));

        QuicConnectionArmTimerEffect currentArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 20)));

        QuicConnectionTransitionResult staleResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: 10,
                QuicConnectionTimerKind.IdleTimeout,
                originalArm.Generation),
            nowTicks: 10);

        Assert.False(staleResult.StateChanged);
        Assert.False(staleResult.HasEffects);
        Assert.Equal(20L, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.True(runtime.TimerState.IsCurrent(QuicConnectionTimerKind.IdleTimeout, currentArm.Generation));
    }
}

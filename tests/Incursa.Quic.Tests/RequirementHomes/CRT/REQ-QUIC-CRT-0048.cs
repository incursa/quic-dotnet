namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0048")]
public sealed class REQ_QUIC_CRT_0048
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DeadlineSchedulerDequeuesTheEarliestDueTimerFirst()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(7);

        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 40))
        {
            scheduler.Apply(handle, runtime, effect);
        }

        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.CloseLifetime, 10))
        {
            scheduler.Apply(handle, runtime, effect);
        }

        Assert.True(scheduler.TryDequeueDueEntry(10, out QuicConnectionRuntimeScheduledTimerEntry firstEntry));
        Assert.Equal(QuicConnectionTimerKind.CloseLifetime, firstEntry.TimerKind);
        Assert.Equal(10L, firstEntry.DueTicks);

        Assert.False(scheduler.TryDequeueDueEntry(39, out _));

        Assert.True(scheduler.TryDequeueDueEntry(40, out QuicConnectionRuntimeScheduledTimerEntry secondEntry));
        Assert.Equal(QuicConnectionTimerKind.IdleTimeout, secondEntry.TimerKind);
        Assert.Equal(40L, secondEntry.DueTicks);
    }
}

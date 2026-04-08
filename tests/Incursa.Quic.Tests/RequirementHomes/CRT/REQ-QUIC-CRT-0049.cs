namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0049")]
public sealed class REQ_QUIC_CRT_0049
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TimerPriorityUsesTheSequenceTieBreakerForEqualDeadlines()
    {
        QuicConnectionTimerPriority earlierSequence = new(1_000, 3);
        QuicConnectionTimerPriority laterSequence = new(1_000, 4);
        QuicConnectionTimerPriority earlierDueTick = new(999, 99);

        Assert.True(earlierSequence < laterSequence);
        Assert.True(earlierSequence <= laterSequence);
        Assert.True(laterSequence > earlierSequence);
        Assert.True(laterSequence >= earlierSequence);
        Assert.True(earlierDueTick < earlierSequence);
        Assert.True(earlierDueTick <= earlierSequence);
        Assert.Equal(0, earlierSequence.CompareTo(new QuicConnectionTimerPriority(1_000, 3)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DeadlineSchedulerUsesArmSequenceToOrderEqualDueTimersDeterministically()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(9);

        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 100))
        {
            scheduler.Apply(handle, runtime, effect);
        }

        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.CloseLifetime, 100))
        {
            scheduler.Apply(handle, runtime, effect);
        }

        Assert.True(scheduler.TryDequeueDueEntry(100, out QuicConnectionRuntimeScheduledTimerEntry firstEntry));
        Assert.True(scheduler.TryDequeueDueEntry(100, out QuicConnectionRuntimeScheduledTimerEntry secondEntry));

        Assert.Equal(QuicConnectionTimerKind.IdleTimeout, firstEntry.TimerKind);
        Assert.Equal(QuicConnectionTimerKind.CloseLifetime, secondEntry.TimerKind);
        Assert.True(firstEntry.Priority < secondEntry.Priority);
    }
}

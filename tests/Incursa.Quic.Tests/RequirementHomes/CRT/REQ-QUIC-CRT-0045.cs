using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0045")]
public sealed class REQ_QUIC_CRT_0045
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DeadlineAdmissionUsesMonotonicTicksForDueTimerComparison()
    {
        long startTicks = Stopwatch.Frequency;
        long intervalTicks = Stopwatch.Frequency / 10;
        FakeMonotonicClock clock = new(startTicks);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(45);

        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, startTicks + intervalTicks))
        {
            scheduler.Apply(handle, runtime, effect);
        }

        Assert.True(scheduler.TryGetNextWait(clock.Ticks, out TimeSpan wait));
        Assert.True(wait > TimeSpan.Zero);
        Assert.False(scheduler.TryDequeueDueEntry(clock.Ticks, out _));

        clock.Advance(intervalTicks);

        Assert.True(scheduler.TryGetNextWait(clock.Ticks, out wait));
        Assert.Equal(TimeSpan.Zero, wait);
        Assert.True(scheduler.TryDequeueDueEntry(clock.Ticks, out QuicConnectionRuntimeScheduledTimerEntry entry));
        Assert.Equal(startTicks + intervalTicks, entry.DueTicks);
    }
}

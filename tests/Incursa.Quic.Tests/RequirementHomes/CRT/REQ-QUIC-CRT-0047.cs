namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0047")]
public sealed class REQ_QUIC_CRT_0047
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TimerArmEffectsAndSchedulerEntriesPreserveAbsoluteDueTicks()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(47);

        QuicConnectionArmTimerEffect arm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(runtime.SetTimerDeadline(QuicConnectionTimerKind.PathValidation, 1_234)));

        Assert.Equal(1_234L, arm.Priority.DueTicks);
        Assert.Equal(1_234L, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));

        scheduler.Apply(handle, runtime, arm);

        Assert.True(scheduler.TryDequeueDueEntry(1_234, out QuicConnectionRuntimeScheduledTimerEntry entry));
        Assert.Equal(1_234L, entry.DueTicks);
        Assert.Equal(1_234L, entry.Priority.DueTicks);
    }
}

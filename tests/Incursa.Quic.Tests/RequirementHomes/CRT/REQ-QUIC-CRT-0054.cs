using System.Threading.Channels;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0054")]
public sealed class REQ_QUIC_CRT_0054
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DueTimerExpirationsReenterTheOwningShardInboxAsRuntimeEvents()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(54);

        QuicConnectionArmTimerEffect arm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 10)));
        scheduler.Apply(handle, runtime, arm);

        Channel<QuicConnectionRuntimeShardWorkItem> inbox = Channel.CreateUnbounded<QuicConnectionRuntimeShardWorkItem>();
        int enqueued = scheduler.EnqueueDueEntries(10, inbox.Writer);

        Assert.Equal(1, enqueued);
        Assert.True(inbox.Reader.TryRead(out QuicConnectionRuntimeShardWorkItem workItem));
        Assert.Equal(handle, workItem.Handle);
        Assert.Same(runtime, workItem.Runtime);

        QuicConnectionTimerExpiredEvent expired = Assert.IsType<QuicConnectionTimerExpiredEvent>(workItem.ConnectionEvent);
        Assert.Equal(10L, expired.ObservedAtTicks);
        Assert.Equal(QuicConnectionTimerKind.IdleTimeout, expired.TimerKind);
        Assert.Equal(arm.Generation, expired.Generation);
    }
}

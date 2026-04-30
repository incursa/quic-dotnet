namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0050")]
public sealed class REQ_QUIC_CRT_0050
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShardSchedulerOwnsWakeupsForMultipleConnectionsAboveTheRuntime()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntimeShard shard = new(0, clock);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        ApplyTimerEffects(shard, new QuicConnectionHandle(50), firstRuntime, QuicConnectionTimerKind.IdleTimeout, 10);
        ApplyTimerEffects(shard, new QuicConnectionHandle(51), secondRuntime, QuicConnectionTimerKind.CloseLifetime, 20);

        Assert.Equal(2, shard.DeadlineScheduler.RegistrationCount);
    }

    private static void ApplyTimerEffects(
        QuicConnectionRuntimeShard shard,
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        QuicConnectionTimerKind timerKind,
        long dueTicks)
    {
        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(timerKind, dueTicks))
        {
            shard.ApplyEffect(handle, runtime, effect);
        }
    }
}

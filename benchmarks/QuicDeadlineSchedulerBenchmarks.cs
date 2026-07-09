// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks shard deadline scheduler shapes that are sensitive to timer re-arm churn.
/// </summary>
[MemoryDiagnoser]
public class QuicDeadlineSchedulerBenchmarks
{
    /// <summary>
    /// Measures repeated re-arming of one timer, where old heap entries become stale.
    /// </summary>
    [Benchmark]
    public int RepeatedRecoveryTimerRearms()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(1);

        ApplyRecoveryRearms(runtime, scheduler, handle, count: 384);

        return scheduler.RegistrationCount ^ scheduler.ScheduledEntryCount;
    }

    /// <summary>
    /// Measures stale-entry pruning when a shard asks how long to wait for the latest re-armed timer.
    /// </summary>
    [Benchmark]
    public long GetNextWaitAfterRecoveryTimerRearms()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(2);

        ApplyRecoveryRearms(runtime, scheduler, handle, count: 384);

        return scheduler.TryGetNextWait(1_000, out TimeSpan wait)
            ? wait.Ticks ^ scheduler.ScheduledEntryCount
            : 0;
    }

    /// <summary>
    /// Measures dequeuing the newest recovery timer after earlier re-arm heap entries became stale.
    /// </summary>
    [Benchmark]
    public long DequeueLatestRecoveryTimerAfterRearms()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(3);

        ApplyRecoveryRearms(runtime, scheduler, handle, count: 384);

        return scheduler.TryDequeueDueEntry(1_383, out QuicConnectionRuntimeScheduledTimerEntry entry)
            ? entry.DueTicks ^ scheduler.RegistrationCount ^ scheduler.ScheduledEntryCount
            : 0;
    }

    private static void ApplyRecoveryRearms(
        QuicConnectionRuntime runtime,
        QuicConnectionRuntimeDeadlineScheduler scheduler,
        QuicConnectionHandle handle,
        int count)
    {
        for (int index = 0; index < count; index++)
        {
            foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.Recovery, 1_000 + index))
            {
                scheduler.Apply(handle, runtime, effect);
            }
        }
    }

    private static QuicConnectionRuntime CreateRuntime()
        => new(CreateState(), new FixedMonotonicClock(0));

    private static QuicConnectionStreamState CreateState()
    {
        return new QuicConnectionStreamState(
            new QuicConnectionStreamStateOptions(
                IsServer: false,
                InitialConnectionReceiveLimit: 4096,
                InitialConnectionSendLimit: 4096,
                InitialIncomingBidirectionalStreamLimit: 16,
                InitialIncomingUnidirectionalStreamLimit: 16,
                InitialPeerBidirectionalStreamLimit: 16,
                InitialPeerUnidirectionalStreamLimit: 16,
                InitialLocalBidirectionalReceiveLimit: 4096,
                InitialPeerBidirectionalReceiveLimit: 4096,
                InitialPeerUnidirectionalReceiveLimit: 4096,
                InitialLocalBidirectionalSendLimit: 4096,
                InitialLocalUnidirectionalSendLimit: 4096,
                InitialPeerBidirectionalSendLimit: 4096));
    }

    private sealed class FixedMonotonicClock(long ticks) : IMonotonicClock
    {
        public long Ticks { get; } = ticks;

        public double Seconds => 0;
    }
}

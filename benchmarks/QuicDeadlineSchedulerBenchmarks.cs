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
        FixedMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(CreateState(), clock);
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(1);

        for (int index = 0; index < 384; index++)
        {
            foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.Recovery, 1_000 + index))
            {
                scheduler.Apply(handle, runtime, effect);
            }
        }

        return scheduler.RegistrationCount ^ scheduler.ScheduledEntryCount;
    }

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

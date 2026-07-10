// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HostedShardSchedulesTimerUpdatesWithoutPublishingTimerEffectObjects()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntimeShard shard = new(
            0,
            clock,
            suppressHostedTimerEffectObjects: true);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 100);
        QuicConnectionHandle handle = new(52);
        List<QuicConnectionEffect> observedEffects = [];
        TaskCompletionSource<bool> transitionObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 200,
                PeerMaxIdleTimeoutMicros: 200,
                CurrentProbeTimeoutMicros: 100),
            nowTicks: 0);

        Task consumer = shard.RunAsync(
            (_, transition) =>
            {
                if (transition.EventKind == QuicConnectionEventKind.LocalCloseRequested)
                {
                    transitionObserved.TrySetResult(true);
                }
            },
            (_, effect) => observedEffects.Add(effect),
            cancellation.Token);

        Assert.True(shard.TryPost(
            handle,
            runtime,
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionCloseMetadata(
                    QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "local close"))));

        await transitionObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(SpinWait.SpinUntil(
            () => shard.DeadlineScheduler.RegistrationCount == 1,
            TimeSpan.FromSeconds(5)));

        cancellation.Cancel();
        await consumer;

        Assert.DoesNotContain(observedEffects, effect =>
            effect is QuicConnectionArmTimerEffect or QuicConnectionCancelTimerEffect);
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

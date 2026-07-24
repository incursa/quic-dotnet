// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0181")]
public sealed class REQ_QUIC_CRT_0181
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ObserveOnlyShardServiceProducesBoundedConnectionEvidence()
    {
        FakeMonotonicClock clock = new(0);
        QuicActorServiceEpochAccumulator accumulator = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            ActorServiceObservationMode =
                QuicActorServiceObservationMode.ObserveOnly,
            ActorServiceEvidenceSink = accumulator,
        });
        await using QuicConnectionRuntimeShard shard = new(7, clock);
        TaskCompletionSource transitionObserved =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        Task consumer = shard.RunAsync(
            (_, _) => transitionObserved.TrySetResult());
        Assert.True(shard.TryPostFlowControlCreditUpdate(
            new QuicConnectionHandle(1),
            runtime));
        await transitionObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await shard.DisposeAsync();
        await consumer;

        QuicActorServiceEpochSummary summary =
            accumulator.CaptureAndReset();
        Assert.True(summary.HasObservation);
        Assert.Equal(1UL, summary.FirstServiceSequence);
        Assert.Equal(1UL, summary.LastServiceSequence);
        Assert.Equal(1UL, summary.ActorTurnCount);
        Assert.Equal(1UL, summary.CompletedTurnCount);
        Assert.Equal(1UL, summary.FlowControlCreditUpdateCount);
        Assert.Equal(1UL, summary.ObservedWakeCount);
        Assert.Equal(1U, summary.MaximumWakePosition);
        Assert.Equal(1UL, summary.QueueDelayObservationCount);
        Assert.True(
            (summary.Validity
                & QuicActorServiceValidity.UsefulWorkUnitsUndefined) != 0);
        Assert.True(
            (summary.Validity
                & QuicActorServiceValidity.MissingRunnableConnectionCount)
            != 0);
        Assert.True(
            (summary.Validity
                & QuicActorServiceValidity.MissingInterServiceGap) != 0);
        Assert.True(
            (summary.Validity
                & QuicActorServiceValidity.MissingDeadlineLateness) == 0);

        QuicActorServiceEpochSummary empty =
            accumulator.CaptureAndReset();
        Assert.False(empty.HasObservation);
        Assert.Equal(0UL, empty.ActorTurnCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ShardTracksPostedOrServicingConnectionContendersWithoutRunnableClaim()
    {
        FakeMonotonicClock clock = new(0);
        RecordingSink sink = new();
        using QuicConnectionRuntime firstRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock);
        using QuicConnectionRuntime secondRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock);
        QuicServerConnectionOptions options = new()
        {
            ActorServiceObservationMode =
                QuicActorServiceObservationMode.ObserveOnly,
            ActorServiceEvidenceSink = sink,
        };
        firstRuntime.ConfigureAdaptiveRuntimePolicy(options);
        secondRuntime.ConfigureAdaptiveRuntimePolicy(options);
        await using QuicConnectionRuntimeShard shard = new(8, clock);

        Assert.True(shard.TryPostFlowControlCreditUpdate(
            new QuicConnectionHandle(11),
            firstRuntime));
        Assert.True(shard.TryPostFlowControlCreditUpdate(
            new QuicConnectionHandle(11),
            firstRuntime));
        Assert.True(shard.TryPostFlowControlCreditUpdate(
            new QuicConnectionHandle(12),
            secondRuntime));
        Assert.Equal(2, shard.ServiceContenderCount);
        Assert.True(shard.ServiceContenderStateValid);
        Task consumer = shard.RunAsync();
        await sink.WaitForCountAsync(3);
        await shard.DisposeAsync();
        await consumer;

        QuicActorServiceObservation[] observations = sink.Observations;
        Assert.Equal(3, observations.Length);
        Assert.Equal(0, shard.ServiceContenderCount);
        Assert.True(shard.ServiceContenderStateValid);
        Assert.All(
            observations,
            observation =>
            {
                Assert.True(
                    (observation.Validity
                        & QuicActorServiceValidity
                            .MissingRunnableConnectionCount) != 0);
            });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ShutdownBeforeConsumerStartDrainsServiceContenderAccounting()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionRuntimeShard shard = new(9);

        Assert.True(shard.TryPostFlowControlCreditUpdate(
            new QuicConnectionHandle(13),
            runtime));
        Assert.Equal(1, shard.ServiceContenderCount);

        await shard.DisposeAsync();

        Assert.Equal(0, shard.ServiceContenderCount);
        Assert.True(shard.ServiceContenderStateValid);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ObservationConfigurationRequiresAnExactModeAndSinkPair()
    {
        using QuicConnectionRuntime missingSink = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => missingSink.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    ActorServiceObservationMode =
                        QuicActorServiceObservationMode.ObserveOnly,
                }));

        using QuicConnectionRuntime disabledWithSink = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => disabledWithSink.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    ActorServiceEvidenceSink =
                        new QuicActorServiceEpochAccumulator(),
                }));

        using QuicConnectionRuntime invalidMode = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<ArgumentOutOfRangeException>(
            () => invalidMode.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    ActorServiceObservationMode =
                        (QuicActorServiceObservationMode)byte.MaxValue,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionCopyPreservesActorObservationModeAndSink()
    {
        QuicActorServiceEpochAccumulator sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            ActorServiceObservationMode =
                QuicActorServiceObservationMode.ObserveOnly,
            ActorServiceEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(
            selectedOptions,
            returnedOptions);

        Assert.Equal(
            QuicActorServiceObservationMode.ObserveOnly,
            selectedOptions.ActorServiceObservationMode);
        Assert.Same(sink, selectedOptions.ActorServiceEvidenceSink);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ThrowingEvidenceSinkCannotInterruptActorProgress()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            ActorServiceObservationMode =
                QuicActorServiceObservationMode.ObserveOnly,
            ActorServiceEvidenceSink = new ThrowingSink(),
        });
        await using QuicConnectionRuntimeShard shard = new(3, clock);
        TaskCompletionSource transitionObserved =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        Task consumer = shard.RunAsync(
            (_, _) => transitionObserved.TrySetResult());
        Assert.True(shard.TryPostFlowControlCreditUpdate(
            new QuicConnectionHandle(2),
            runtime));
        await transitionObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await shard.DisposeAsync();
        await consumer;
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConsecutiveServiceRecordsConnectionLocalGapWithoutRunnableClaim()
    {
        FakeMonotonicClock clock = new(0);
        RecordingSink sink = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            ActorServiceObservationMode =
                QuicActorServiceObservationMode.ObserveOnly,
            ActorServiceEvidenceSink = sink,
        });
        await using QuicConnectionRuntimeShard shard = new(4, clock);
        Task consumer = shard.RunAsync();

        Assert.True(shard.TryPostFlowControlCreditUpdate(
            new QuicConnectionHandle(3),
            runtime));
        Assert.True(shard.TryPostFlowControlCreditUpdate(
            new QuicConnectionHandle(3),
            runtime));
        await sink.WaitForCountAsync(2);
        await shard.DisposeAsync();
        await consumer;

        QuicActorServiceObservation[] observations = sink.Observations;
        Assert.Equal(2, observations.Length);
        Assert.Null(observations[0].InterServiceGapMicros);
        Assert.True(
            (observations[0].Validity
                & QuicActorServiceValidity.MissingInterServiceGap) != 0);
        Assert.NotNull(observations[1].InterServiceGapMicros);
        Assert.True(
            (observations[1].Validity
                & QuicActorServiceValidity.MissingInterServiceGap) == 0);
        Assert.All(
            observations,
            observation =>
            {
                Assert.Null(observation.DeadlineLatenessMicros);
                Assert.True(
                    (observation.Validity
                        & QuicActorServiceValidity
                            .MissingDeadlineLateness) == 0);
                Assert.True(
                    (observation.Validity
                        & QuicActorServiceValidity
                            .MissingRunnableConnectionCount) != 0);
            });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ScheduledTimerRecordsExactDeadlineLateness()
    {
        long dueTicks = Stopwatch.Frequency;
        long latenessTicks = Stopwatch.Frequency / 100;
        FakeMonotonicClock clock = new(dueTicks + latenessTicks);
        RecordingSink sink = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            ActorServiceObservationMode =
                QuicActorServiceObservationMode.ObserveOnly,
            ActorServiceEvidenceSink = sink,
        });
        await using QuicConnectionRuntimeShard shard = new(5, clock);
        shard.ApplyEffect(
            new QuicConnectionHandle(4),
            runtime,
            new QuicConnectionArmTimerEffect(
                QuicConnectionTimerKind.ApplicationSendDelay,
                Generation: 1,
                new QuicConnectionTimerPriority(dueTicks, Sequence: 1)));

        Task consumer = shard.RunAsync();
        await sink.WaitForCountAsync(1);
        await shard.DisposeAsync();
        await consumer;

        QuicActorServiceObservation observation =
            Assert.Single(sink.Observations);
        Assert.Equal(QuicActorWorkKind.Timer, observation.WorkKind);
        ulong expectedLatenessMicros =
            ((ulong)latenessTicks * 1_000_000UL)
            / (ulong)Stopwatch.Frequency;
        Assert.Equal(
            expectedLatenessMicros,
            observation.DeadlineLatenessMicros);
        Assert.True(
            (observation.Validity
                & QuicActorServiceValidity.MissingDeadlineLateness) == 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EpochAccumulatorRetainsClosedKindsWakeChangesAndFollowOns()
    {
        QuicActorServiceEpochAccumulator accumulator = new();
        QuicActorServiceObservation first = CreateObservation(
            serviceSequence: 5,
            wakeSequence: 2,
            QuicActorWorkKind.StreamWrite,
            queueDelayMicros: 10,
            serviceTimeMicros: 20,
            effectCount: 2,
            applicationSendFollowOnCount: 3,
            interServiceGapMicros: 10);
        QuicActorServiceObservation second = CreateObservation(
            serviceSequence: 6,
            wakeSequence: 3,
            QuicActorWorkKind.Timer,
            queueDelayMicros: null,
            serviceTimeMicros: 40,
            effectCount: 1,
            applicationSendFollowOnCount: 0,
            interServiceGapMicros: 20,
            deadlineLatenessMicros: 5);

        Assert.True(accumulator.TryPublish(in first));
        Assert.True(accumulator.TryPublish(in second));
        QuicActorServiceEpochSummary summary =
            accumulator.CaptureAndReset();

        Assert.Equal(2UL, summary.ActorTurnCount);
        Assert.Equal(1UL, summary.StreamWriteCount);
        Assert.Equal(1UL, summary.TimerCount);
        Assert.Equal(2UL, summary.ObservedWakeCount);
        Assert.Equal(60UL, summary.TotalServiceTimeMicros);
        Assert.Equal(40UL, summary.MaximumServiceTimeMicros);
        Assert.Equal(1UL, summary.QueueDelayObservationCount);
        Assert.Equal(3UL, summary.TotalEffectCount);
        Assert.Equal(3UL, summary.ApplicationSendFollowOnCount);
        Assert.Equal(2UL, summary.InterServiceGapObservationCount);
        Assert.Equal(30UL, summary.TotalInterServiceGapMicros);
        Assert.Equal(20UL, summary.MaximumInterServiceGapMicros);
        Assert.Equal(1UL, summary.DeadlineLatenessObservationCount);
        Assert.Equal(5UL, summary.TotalDeadlineLatenessMicros);
        Assert.Equal(5UL, summary.MaximumDeadlineLatenessMicros);
        Assert.True(
            (summary.Validity
                & QuicActorServiceValidity.MissingQueueDelay) != 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ObservationAndEpochSummaryPassSchemaAndSemanticValidation()
    {
        string repoRoot =
            AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"actor-service-validator-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            QuicActorServiceObservation observation = CreateObservation(
                serviceSequence: 1,
                wakeSequence: 1,
                QuicActorWorkKind.FlowControlCreditUpdate,
                queueDelayMicros: 5,
                serviceTimeMicros: 7,
                effectCount: 0,
                applicationSendFollowOnCount: 0);
            QuicActorServiceEpochAccumulator accumulator = new();
            Assert.True(accumulator.TryPublish(in observation));
            QuicActorServiceEpochSummary summary =
                accumulator.CaptureAndReset();
            JsonSerializerOptions options = new(JsonSerializerDefaults.Web);
            options.Converters.Add(new JsonStringEnumConverter());
            string observationPath = Path.Combine(
                temporaryDirectory,
                "actor-service-observations.jsonl");
            string epochPath = Path.Combine(
                temporaryDirectory,
                "actor-service-epoch.json");
            File.WriteAllText(
                observationPath,
                JsonSerializer.Serialize(observation, options));
            File.WriteAllText(
                epochPath,
                JsonSerializer.Serialize(summary, options));

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimeActorServiceEvidence.ps1",
                    "-ObservationPath",
                    observationPath,
                    "-EpochSummaryPath",
                    epochPath);

            Assert.True(result.ExitCode == 0, result.Output);
            using JsonDocument validation = JsonDocument.Parse(
                result.Output);
            Assert.True(
                validation.RootElement.GetProperty("valid").GetBoolean());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("observationRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("actorTurnCount")
                    .GetInt32());
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private static QuicActorServiceObservation CreateObservation(
        ulong serviceSequence,
        ulong wakeSequence,
        QuicActorWorkKind workKind,
        ulong? queueDelayMicros,
        ulong serviceTimeMicros,
        uint effectCount,
        uint applicationSendFollowOnCount,
        ulong? interServiceGapMicros = null,
        ulong? deadlineLatenessMicros = null)
    {
        QuicActorServiceValidity validity =
            QuicActorServiceValidity.MissingRunnableConnectionCount
            | QuicActorServiceValidity.MissingOldestShardItemAge
            | QuicActorServiceValidity.UsefulWorkUnitsUndefined;
        if (!queueDelayMicros.HasValue)
        {
            validity |= QuicActorServiceValidity.MissingQueueDelay;
        }
        if (!interServiceGapMicros.HasValue)
        {
            validity |= QuicActorServiceValidity.MissingInterServiceGap;
        }
        if (workKind == QuicActorWorkKind.Timer
            && !deadlineLatenessMicros.HasValue)
        {
            validity |= QuicActorServiceValidity.MissingDeadlineLateness;
        }

        return new QuicActorServiceObservation(
            serviceSequence,
            ShardIndex: 1,
            wakeSequence,
            WakePosition: 1,
            QuicActorWakeCompletion.Synchronous,
            QuicActorWakeSource.Inbox,
            workKind,
            QuicActorServiceDisposition.Completed,
            queueDelayMicros,
            serviceTimeMicros,
            PendingWorkItemsAfterDequeue: 0,
            effectCount,
            applicationSendFollowOnCount,
            FlowControlFollowOnCount: 0,
            StreamCapacityFollowOnCount: 0,
            QuicConnectionPhase.Active,
            DisposalStarted: false,
            validity,
            interServiceGapMicros,
            deadlineLatenessMicros);
    }

    private sealed class ThrowingSink : IQuicActorServiceEvidenceSink
    {
        public bool TryPublish(
            in QuicActorServiceObservation observation)
            => throw new InvalidOperationException("diagnostic sink failure");
    }

    private sealed class RecordingSink : IQuicActorServiceEvidenceSink
    {
        private readonly object gate = new();
        private readonly List<QuicActorServiceObservation> observations = [];
        private TaskCompletionSource changed =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal QuicActorServiceObservation[] Observations
        {
            get
            {
                lock (gate)
                {
                    return [.. observations];
                }
            }
        }

        public bool TryPublish(
            in QuicActorServiceObservation observation)
        {
            lock (gate)
            {
                observations.Add(observation);
                changed.TrySetResult();
                changed = new(
                    TaskCreationOptions.RunContinuationsAsynchronously);
            }

            return true;
        }

        internal async Task WaitForCountAsync(int expectedCount)
        {
            using CancellationTokenSource timeout =
                new(TimeSpan.FromSeconds(5));
            while (true)
            {
                Task wait;
                lock (gate)
                {
                    if (observations.Count >= expectedCount)
                    {
                        return;
                    }

                    wait = changed.Task;
                }

                await wait.WaitAsync(timeout.Token);
            }
        }
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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

        QuicActorServiceEpochSummary empty =
            accumulator.CaptureAndReset();
        Assert.False(empty.HasObservation);
        Assert.Equal(0UL, empty.ActorTurnCount);
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
            applicationSendFollowOnCount: 3);
        QuicActorServiceObservation second = CreateObservation(
            serviceSequence: 6,
            wakeSequence: 3,
            QuicActorWorkKind.Timer,
            queueDelayMicros: null,
            serviceTimeMicros: 40,
            effectCount: 1,
            applicationSendFollowOnCount: 0);

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
        uint applicationSendFollowOnCount)
    {
        QuicActorServiceValidity validity =
            QuicActorServiceValidity.MissingRunnableConnectionCount
            | QuicActorServiceValidity.MissingOldestShardItemAge
            | QuicActorServiceValidity.MissingDeadlineLateness
            | QuicActorServiceValidity.UsefulWorkUnitsUndefined;
        if (!queueDelayMicros.HasValue)
        {
            validity |= QuicActorServiceValidity.MissingQueueDelay;
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
            validity);
    }

    private sealed class ThrowingSink : IQuicActorServiceEvidenceSink
    {
        public bool TryPublish(
            in QuicActorServiceObservation observation)
            => throw new InvalidOperationException("diagnostic sink failure");
    }
}

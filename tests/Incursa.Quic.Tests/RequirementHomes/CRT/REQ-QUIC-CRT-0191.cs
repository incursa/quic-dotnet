// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0191")]
public sealed class REQ_QUIC_CRT_0191
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedEarlyDelayAddsOneWaitWhenBacklogExists()
    {
        QuicAdaptiveBackpressurePolicyDecision decision =
            QuicAdaptiveBackpressurePolicy.Evaluate(
                QuicAdaptiveBackpressureObservationMode.Disabled,
                QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
                queuedOperationCount: 1,
                retainedCapacityBytes: 64,
                QuicAdaptiveBackpressureValidity.None,
                lifecycleGuard: false,
                continuationAvailable: true,
                admissionAlreadyEvaluated: false);

        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
            decision.SelectedValue);
        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
            decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveBackpressureSelectionSource.Forced,
            decision.SelectionSource);
        Assert.True(decision.DelayApplied);
        Assert.False(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackNeverAddsTheWait()
    {
        QuicAdaptiveBackpressurePolicyDecision decision =
            QuicAdaptiveBackpressurePolicy.Evaluate(
                QuicAdaptiveBackpressureObservationMode.Disabled,
                QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
                queuedOperationCount: 2,
                retainedCapacityBytes: 128,
                QuicAdaptiveBackpressureValidity.None,
                lifecycleGuard: false,
                continuationAvailable: true,
                admissionAlreadyEvaluated: false);

        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.False(decision.DelayApplied);
        Assert.False(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowRecommendsWithoutApplyingTheWait()
    {
        QuicAdaptiveBackpressurePolicyDecision decision =
            QuicAdaptiveBackpressurePolicy.Evaluate(
                QuicAdaptiveBackpressureObservationMode.Shadow,
                forcedValue: null,
                queuedOperationCount: 1,
                retainedCapacityBytes: 64,
                QuicAdaptiveBackpressureValidity.None,
                lifecycleGuard: false,
                continuationAvailable: true,
                admissionAlreadyEvaluated: false);

        Assert.True(decision.HasShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
            decision.ShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
            decision.SelectedValue);
        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.False(decision.DelayApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EarlyDelayIsConditionalAndLatchedOncePerAdmission()
    {
        QuicAdaptiveBackpressurePolicyDecision noBacklog =
            QuicAdaptiveBackpressurePolicy.Evaluate(
                QuicAdaptiveBackpressureObservationMode.Disabled,
                QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
                queuedOperationCount: 0,
                retainedCapacityBytes: 0,
                QuicAdaptiveBackpressureValidity.None,
                lifecycleGuard: false,
                continuationAvailable: true,
                admissionAlreadyEvaluated: false);
        QuicAdaptiveBackpressurePolicyDecision alreadyEvaluated =
            QuicAdaptiveBackpressurePolicy.Evaluate(
                QuicAdaptiveBackpressureObservationMode.Disabled,
                QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
                queuedOperationCount: 1,
                retainedCapacityBytes: 64,
                QuicAdaptiveBackpressureValidity.None,
                lifecycleGuard: false,
                continuationAvailable: true,
                admissionAlreadyEvaluated: true);

        Assert.False(noBacklog.DelayApplied);
        Assert.Equal(
            QuicAdaptiveBackpressureReasonCode.NoBacklog,
            noBacklog.ReasonCode);
        Assert.False(alreadyEvaluated.DelayApplied);
        Assert.Equal(
            QuicAdaptiveBackpressureReasonCode.DelayAlreadyApplied,
            alreadyEvaluated.ReasonCode);
    }

    [Theory]
    [InlineData(
        (byte)QuicAdaptiveBackpressureValidity.MissingRequiredInput,
        (byte)QuicAdaptiveBackpressureReasonCode.MissingInput)]
    [InlineData(
        (byte)QuicAdaptiveBackpressureValidity.StaleRequiredInput,
        (byte)QuicAdaptiveBackpressureReasonCode.StaleInput)]
    [InlineData(
        (byte)QuicAdaptiveBackpressureValidity.ArithmeticSaturated,
        (byte)QuicAdaptiveBackpressureReasonCode.ArithmeticSaturated)]
    [InlineData(
        (byte)QuicAdaptiveBackpressureValidity.Contradictory,
        (byte)QuicAdaptiveBackpressureReasonCode.Contradictory)]
    [InlineData(
        (byte)QuicAdaptiveBackpressureValidity.OutOfDomain,
        (byte)QuicAdaptiveBackpressureReasonCode.OutOfDomain)]
    [InlineData(
        (byte)QuicAdaptiveBackpressureValidity.InvalidInput,
        (byte)QuicAdaptiveBackpressureReasonCode.InvalidInput)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidInputsFallBackEvenWhenForced(
        byte validityValue,
        byte expectedReasonValue)
    {
        QuicAdaptiveBackpressureValidity validity =
            (QuicAdaptiveBackpressureValidity)validityValue;
        QuicAdaptiveBackpressureReasonCode expectedReason =
            (QuicAdaptiveBackpressureReasonCode)expectedReasonValue;
        QuicAdaptiveBackpressurePolicyDecision decision =
            QuicAdaptiveBackpressurePolicy.Evaluate(
                QuicAdaptiveBackpressureObservationMode.Shadow,
                QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
                queuedOperationCount: 1,
                retainedCapacityBytes: 64,
                validity,
                lifecycleGuard: false,
                continuationAvailable: true,
                admissionAlreadyEvaluated: false);

        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
            decision.SelectedValue);
        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveBackpressureSelectionSource.SafetyOverride,
            decision.SelectionSource);
        Assert.Equal(expectedReason, decision.ReasonCode);
        Assert.False(decision.DelayApplied);
        Assert.True(decision.FallbackApplied);
    }

    [Theory]
    [InlineData(
        true,
        true,
        (byte)QuicAdaptiveBackpressureReasonCode.LifecycleGuard)]
    [InlineData(
        false,
        false,
        (byte)QuicAdaptiveBackpressureReasonCode.ContinuationUnavailable)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProgressGuardsOverrideForcedDelay(
        bool lifecycleGuard,
        bool continuationAvailable,
        byte expectedReasonValue)
    {
        QuicAdaptiveBackpressureReasonCode expectedReason =
            (QuicAdaptiveBackpressureReasonCode)expectedReasonValue;
        QuicAdaptiveBackpressurePolicyDecision decision =
            QuicAdaptiveBackpressurePolicy.Evaluate(
                QuicAdaptiveBackpressureObservationMode.Disabled,
                QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
                queuedOperationCount: 1,
                retainedCapacityBytes: 64,
                QuicAdaptiveBackpressureValidity.None,
                lifecycleGuard,
                continuationAvailable,
                admissionAlreadyEvaluated: false);

        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(expectedReason, decision.ReasonCode);
        Assert.False(decision.DelayApplied);
        Assert.True(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidModeAndSinkPairingsAreRejected()
    {
        using QuicConnectionRuntime missingSink =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => missingSink.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    AdaptiveBackpressureObservationMode =
                        QuicAdaptiveBackpressureObservationMode
                            .ObserveOnly,
                }));

        using QuicConnectionRuntime disabledWithSink =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => disabledWithSink.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    AdaptiveBackpressureEvidenceSink =
                        new RecordingBackpressureSink(),
                }));

        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicAdaptiveBackpressurePolicy
                .CreateConfiguredSnapshot(
                    (QuicAdaptiveBackpressureObservationMode)byte.MaxValue,
                    forcedValue: null));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicAdaptiveBackpressurePolicy
                .CreateConfiguredSnapshot(
                    QuicAdaptiveBackpressureObservationMode.Disabled,
                    (QuicAdaptiveBackpressurePolicyValue)byte.MaxValue));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BehaviorDistinctAdjacentAxisForcingIsRejected()
    {
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ForcedAdaptiveBackpressurePolicyValue =
                        QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
                    ForcedBufferCopyPolicyValue =
                        QuicBufferCopyPolicyValue.MemoryConservative,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EpochRetainsConfiguredPolicyWithoutAnAdmission()
    {
        QuicAdaptiveBackpressureConfiguredPolicySnapshot snapshot =
            QuicAdaptiveBackpressurePolicy.CreateConfiguredSnapshot(
                QuicAdaptiveBackpressureObservationMode.Shadow,
                forcedValue: null);
        QuicAdaptiveBackpressureEpochAccumulator accumulator =
            new(in snapshot);

        QuicAdaptiveBackpressureEpochSummary summary =
            accumulator.CaptureAndReset();

        Assert.False(summary.HasObservation);
        Assert.Equal(
            QuicAdaptiveBackpressureObservationMode.Shadow,
            summary.PolicySnapshot.Mode);
        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
            summary.PolicySnapshot.SelectedValue);
        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            summary.PolicySnapshot.AppliedValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ObservationEpochAndRawPassVersionedSchemas()
    {
        QuicAdaptiveBackpressureConfiguredPolicySnapshot snapshot =
            QuicAdaptiveBackpressurePolicy.CreateConfiguredSnapshot(
                QuicAdaptiveBackpressureObservationMode.ObserveOnly,
                forcedValue: null);
        QuicAdaptiveBackpressureObservation observation = new(
            OperationSequence: 1,
            RequestId: 1,
            QuicAdaptiveBackpressureObservationMode.ObserveOnly,
            ForcedValue: null,
            ShadowRecommendation: null,
            QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            QuicAdaptiveBackpressurePolicyValue.LegacyCurrent,
            QuicAdaptiveBackpressureSelectionSource.LegacyCurrent,
            QuicAdaptiveBackpressureReasonCode.ObserveOnly,
            QuicAdaptiveBackpressureSafetyOverride.None,
            QuicAdaptiveBackpressureDecisionBoundary
                .NewApplicationAdmission,
            QuicAdaptiveBackpressureLatchLifetime.ApplicationAdmission,
            FallbackApplied: false,
            DelayApplied: false,
            QueuedOperationCount: 0,
            RetainedCapacityBytes: 0,
            QuicConnectionPhase.Active,
            DisposalStarted: false,
            QuicAdaptiveBackpressureValidity.None);
        QuicAdaptiveBackpressureEpochAccumulator accumulator =
            new(in snapshot);
        Assert.True(accumulator.TryPublish(in observation));
        QuicAdaptiveBackpressureEpochSummary epoch =
            accumulator.CaptureAndReset();

        string repoRoot =
            AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"backpressure-schema-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        try
        {
            JsonSerializerOptions jsonOptions =
                new(JsonSerializerDefaults.Web);
            jsonOptions.Converters.Add(new JsonStringEnumConverter());
            string observationPath =
                Path.Combine(temporaryDirectory, "observation.json");
            string epochPath =
                Path.Combine(temporaryDirectory, "epoch.json");
            string rawPath =
                Path.Combine(temporaryDirectory, "raw.json");
            File.WriteAllText(
                observationPath,
                JsonSerializer.Serialize(observation, jsonOptions));
            File.WriteAllText(
                epochPath,
                JsonSerializer.Serialize(epoch, jsonOptions));
            File.WriteAllText(
                rawPath,
                JsonSerializer.Serialize(
                    new
                    {
                        schemaVersion =
                            "quic-adaptive-backpressure-raw-v1",
                        connectionKey = "connection-0001",
                        observation,
                    },
                    jsonOptions));

            string schemas = Path.Combine(repoRoot, "schemas");
            string command =
                $"$observationValid = Get-Content -LiteralPath {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(observationPath)} -Raw | Test-Json -SchemaFile {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(Path.Combine(schemas, "adaptive-runtime-backpressure-observation-v1.schema.json"))}; "
                + $"$epochValid = Get-Content -LiteralPath {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(epochPath)} -Raw | Test-Json -SchemaFile {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(Path.Combine(schemas, "adaptive-runtime-backpressure-epoch-v1.schema.json"))}; "
                + $"$rawValid = Get-Content -LiteralPath {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(rawPath)} -Raw | Test-Json -SchemaFile {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(Path.Combine(schemas, "adaptive-runtime-backpressure-raw-v1.schema.json"))}; "
                + "if (-not ($observationValid -and $epochValid -and $rawValid)) { exit 1 }";
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport
                    .RunPowerShellCommand(command);

            Assert.True(result.ExitCode == 0, result.Output);
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeDelaysExactlyOneDispatcherTurn()
    {
        await using QuicConnectionRuntime runtime =
            CreateRuntimeWithPostedWrites(
                out Queue<PostedStreamWrite> postedWrites,
                out RecordingBackpressureSink sink);
        Assert.True(
            runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId firstStreamId,
                out _));
        Assert.True(
            runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId secondStreamId,
                out _));

        Task firstWrite = runtime.WriteStreamAsync(
            firstStreamId.Value,
            new byte[16]).AsTask();
        TransitionNext(runtime, postedWrites, nowTicks: 20);
        await firstWrite;

        Task secondWrite = runtime.WriteStreamAsync(
            secondStreamId.Value,
            new byte[16]).AsTask();
        Assert.Single(postedWrites);
        TransitionNext(runtime, postedWrites, nowTicks: 21);

        Assert.False(secondWrite.IsCompleted);
        Assert.Single(postedWrites);
        QuicAdaptiveBackpressureObservation observation =
            Assert.Single(
                sink.Observations,
                static candidate => candidate.DelayApplied);
        Assert.True(observation.DelayApplied);
        Assert.Equal(
            QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
            observation.AppliedValue);

        TransitionNext(runtime, postedWrites, nowTicks: 22);
        await secondWrite;

        Assert.Empty(postedWrites);
        Assert.Equal(2, sink.Observations.Count);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeForceLegacyRollbackAdmitsWithoutExtraTurn()
    {
        await using QuicConnectionRuntime runtime =
            CreateRuntimeWithPostedWrites(
                out Queue<PostedStreamWrite> postedWrites,
                out _,
                QuicAdaptiveBackpressurePolicyValue.LegacyCurrent);
        Assert.True(
            runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId firstStreamId,
                out _));
        Assert.True(
            runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId secondStreamId,
                out _));

        Task firstWrite = runtime.WriteStreamAsync(
            firstStreamId.Value,
            new byte[16]).AsTask();
        TransitionNext(runtime, postedWrites, nowTicks: 20);
        await firstWrite;

        Task secondWrite = runtime.WriteStreamAsync(
            secondStreamId.Value,
            new byte[16]).AsTask();
        TransitionNext(runtime, postedWrites, nowTicks: 21);
        await secondWrite;

        Assert.Empty(postedWrites);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ThrowingObservationSinkCannotChangeAdmission()
    {
        await using QuicConnectionRuntime runtime =
            CreateRuntimeWithPostedWrites(
                out Queue<PostedStreamWrite> postedWrites,
                out _,
                QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
                new ThrowingBackpressureSink());
        Assert.True(
            runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId firstStreamId,
                out _));
        Assert.True(
            runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId secondStreamId,
                out _));

        Task firstWrite = runtime.WriteStreamAsync(
            firstStreamId.Value,
            new byte[16]).AsTask();
        TransitionNext(runtime, postedWrites, nowTicks: 20);
        await firstWrite;

        Task delayedWrite = runtime.WriteStreamAsync(
            secondStreamId.Value,
            new byte[16]).AsTask();
        TransitionNext(runtime, postedWrites, nowTicks: 21);
        Assert.False(delayedWrite.IsCompleted);
        TransitionNext(runtime, postedWrites, nowTicks: 22);
        await delayedWrite;

        Assert.Empty(postedWrites);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task CancellationWinsAfterTheDelayWasPosted()
    {
        await using QuicConnectionRuntime runtime =
            CreateRuntimeWithPostedWrites(
                out Queue<PostedStreamWrite> postedWrites,
                out _);
        Assert.True(
            runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId firstStreamId,
                out _));
        Assert.True(
            runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId secondStreamId,
                out _));
        Task firstWrite = runtime.WriteStreamAsync(
            firstStreamId.Value,
            new byte[16]).AsTask();
        TransitionNext(runtime, postedWrites, nowTicks: 20);
        await firstWrite;

        using CancellationTokenSource cancellation = new();
        Task delayedWrite = runtime.WriteStreamAsync(
            secondStreamId.Value,
            new byte[16],
            cancellation.Token).AsTask();
        TransitionNext(runtime, postedWrites, nowTicks: 21);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await delayedWrite);
        TransitionNext(runtime, postedWrites, nowTicks: 22);
        Assert.Empty(postedWrites);
    }

    private static QuicConnectionRuntime CreateRuntimeWithPostedWrites(
        out Queue<PostedStreamWrite> postedWrites,
        out RecordingBackpressureSink sink,
        QuicAdaptiveBackpressurePolicyValue forcedValue =
            QuicAdaptiveBackpressurePolicyValue.EarlyDelay,
        IQuicAdaptiveBackpressureEvidenceSink? evidenceSink = null)
    {
        QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath(
                    connectionSendLimit: 8_192,
                    localBidirectionalSendLimit: 8_192);
        postedWrites = new();
        Queue<PostedStreamWrite> capturedWrites = postedWrites;
        runtime.SetStreamWriteDispatcher(
            (requestId, actionKind, streamId, streamData, streamDataSuffix) =>
            {
                capturedWrites.Enqueue(new(
                    requestId,
                    actionKind,
                    streamId,
                    streamData,
                    streamDataSuffix));
                return true;
            });
        sink = new();
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ForcedAdaptiveBackpressurePolicyValue =
                    forcedValue,
                AdaptiveBackpressureObservationMode =
                    QuicAdaptiveBackpressureObservationMode.Shadow,
                AdaptiveBackpressureEvidenceSink =
                    evidenceSink ?? sink,
            });
        return runtime;
    }

    private static void TransitionNext(
        QuicConnectionRuntime runtime,
        Queue<PostedStreamWrite> postedWrites,
        long nowTicks)
    {
        PostedStreamWrite posted = postedWrites.Dequeue();
        _ = runtime.TransitionStreamWrite(
            posted.RequestId,
            posted.ActionKind,
            posted.StreamId,
            posted.StreamData,
            posted.StreamDataSuffix,
            nowTicks);
    }

    private readonly record struct PostedStreamWrite(
        long RequestId,
        QuicConnectionStreamActionKind ActionKind,
        ulong StreamId,
        ReadOnlyMemory<byte> StreamData,
        ReadOnlyMemory<byte> StreamDataSuffix);

    private sealed class RecordingBackpressureSink :
        IQuicAdaptiveBackpressureEvidenceSink
    {
        internal List<QuicAdaptiveBackpressureObservation> Observations
        {
            get;
        } = [];

        public bool TryPublish(
            in QuicAdaptiveBackpressureObservation observation)
        {
            Observations.Add(observation);
            return true;
        }
    }

    private sealed class ThrowingBackpressureSink :
        IQuicAdaptiveBackpressureEvidenceSink
    {
        public bool TryPublish(
            in QuicAdaptiveBackpressureObservation observation)
            => throw new InvalidOperationException("diagnostic sink failure");
    }
}

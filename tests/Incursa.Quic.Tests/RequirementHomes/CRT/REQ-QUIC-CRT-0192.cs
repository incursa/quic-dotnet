// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0192")]
public sealed class REQ_QUIC_CRT_0192
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedPromptRemovesOnlyTheEligibleLegacyDelay()
    {
        QuicPacketFlushCadencePolicyDecision decision =
            QuicPacketFlushCadencePolicy.Evaluate(
                QuicPacketFlushCadenceObservationMode.Disabled,
                QuicPacketFlushCadencePolicyValue.Prompt,
                streamPayloadLength: 16,
                queuedWriteCount: 0,
                finishWrites: false,
                addressValidated: true,
                retransmissionPending: false,
                lifecycleGuard: false,
                legacyDelayThresholdBytes: 32);

        Assert.True(decision.LegacyDelayEligible);
        Assert.False(decision.DelayApplied);
        Assert.True(decision.PromptFlushApplied);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.Prompt,
            decision.SelectedValue);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.Prompt,
            decision.AppliedValue);
        Assert.Equal(
            QuicPacketFlushCadenceSelectionSource.Forced,
            decision.SelectionSource);
        Assert.Equal(
            QuicPacketFlushCadenceReasonCode.PromptFlush,
            decision.ReasonCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackRetainsTheExistingDelay()
    {
        QuicPacketFlushCadencePolicyDecision decision =
            QuicPacketFlushCadencePolicy.Evaluate(
                QuicPacketFlushCadenceObservationMode.Disabled,
                QuicPacketFlushCadencePolicyValue.LegacyCurrent,
                streamPayloadLength: 16,
                queuedWriteCount: 0,
                finishWrites: false,
                addressValidated: true,
                retransmissionPending: false,
                lifecycleGuard: false,
                legacyDelayThresholdBytes: 32);

        Assert.True(decision.LegacyDelayEligible);
        Assert.True(decision.DelayApplied);
        Assert.False(decision.PromptFlushApplied);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicPacketFlushCadenceReasonCode.LegacyDelay,
            decision.ReasonCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowRecommendsPromptWhileApplyingLegacyDelay()
    {
        QuicPacketFlushCadencePolicyDecision decision =
            QuicPacketFlushCadencePolicy.Evaluate(
                QuicPacketFlushCadenceObservationMode.Shadow,
                forcedValue: null,
                streamPayloadLength: 16,
                queuedWriteCount: 0,
                finishWrites: false,
                addressValidated: true,
                retransmissionPending: false,
                lifecycleGuard: false,
                legacyDelayThresholdBytes: 32);

        Assert.True(decision.HasShadowRecommendation);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.Prompt,
            decision.ShadowRecommendation);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.Prompt,
            decision.SelectedValue);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.True(decision.DelayApplied);
        Assert.False(decision.PromptFlushApplied);
    }

    [Theory]
    [InlineData(
        (byte)QuicPacketFlushCadenceValidity.MissingRequiredInput,
        (byte)QuicPacketFlushCadenceReasonCode.MissingInput)]
    [InlineData(
        (byte)QuicPacketFlushCadenceValidity.StaleRequiredInput,
        (byte)QuicPacketFlushCadenceReasonCode.StaleInput)]
    [InlineData(
        (byte)QuicPacketFlushCadenceValidity.ArithmeticSaturated,
        (byte)QuicPacketFlushCadenceReasonCode.ArithmeticSaturated)]
    [InlineData(
        (byte)QuicPacketFlushCadenceValidity.Contradictory,
        (byte)QuicPacketFlushCadenceReasonCode.Contradictory)]
    [InlineData(
        (byte)QuicPacketFlushCadenceValidity.OutOfDomain,
        (byte)QuicPacketFlushCadenceReasonCode.OutOfDomain)]
    [InlineData(
        (byte)QuicPacketFlushCadenceValidity.InvalidInput,
        (byte)QuicPacketFlushCadenceReasonCode.InvalidInput)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidInputsFallBackEvenWhenPromptIsForced(
        byte validityValue,
        byte expectedReasonValue)
    {
        QuicPacketFlushCadencePolicyDecision decision =
            QuicPacketFlushCadencePolicy.Evaluate(
                QuicPacketFlushCadenceObservationMode.Shadow,
                QuicPacketFlushCadencePolicyValue.Prompt,
                streamPayloadLength: 16,
                queuedWriteCount: 0,
                finishWrites: false,
                addressValidated: true,
                retransmissionPending: false,
                lifecycleGuard: false,
                legacyDelayThresholdBytes: 32,
                (QuicPacketFlushCadenceValidity)validityValue);

        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.Prompt,
            decision.SelectedValue);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicPacketFlushCadenceSelectionSource.SafetyOverride,
            decision.SelectionSource);
        Assert.Equal(
            (QuicPacketFlushCadenceReasonCode)expectedReasonValue,
            decision.ReasonCode);
        Assert.True(decision.FallbackApplied);
        Assert.False(decision.PromptFlushApplied);
    }

    [Theory]
    [InlineData(
        true,
        false,
        true,
        (byte)QuicPacketFlushCadenceReasonCode.LifecycleGuard)]
    [InlineData(
        false,
        true,
        true,
        (byte)QuicPacketFlushCadenceReasonCode.RetransmissionGuard)]
    [InlineData(
        false,
        false,
        false,
        (byte)QuicPacketFlushCadenceReasonCode.AddressValidationGuard)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SafetyGuardsOverrideForcedPrompt(
        bool lifecycleGuard,
        bool retransmissionPending,
        bool addressValidated,
        byte expectedReasonValue)
    {
        QuicPacketFlushCadencePolicyDecision decision =
            QuicPacketFlushCadencePolicy.Evaluate(
                QuicPacketFlushCadenceObservationMode.Disabled,
                QuicPacketFlushCadencePolicyValue.Prompt,
                streamPayloadLength: 16,
                queuedWriteCount: 0,
                finishWrites: false,
                addressValidated,
                retransmissionPending,
                lifecycleGuard,
                legacyDelayThresholdBytes: 32);

        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            (QuicPacketFlushCadenceReasonCode)expectedReasonValue,
            decision.ReasonCode);
        Assert.True(decision.FallbackApplied);
        Assert.False(decision.PromptFlushApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidConfigurationAndAdjacentTreatmentAreRejected()
    {
        using QuicConnectionRuntime missingSink =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => missingSink.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    PacketFlushCadenceObservationMode =
                        QuicPacketFlushCadenceObservationMode.ObserveOnly,
                }));

        using QuicConnectionRuntime disabledWithSink =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => disabledWithSink.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    PacketFlushCadenceEvidenceSink =
                        new RecordingPacketFlushSink(),
                }));

        using QuicConnectionRuntime adjacent =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => adjacent.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ForcedPacketFlushCadencePolicyValue =
                        QuicPacketFlushCadencePolicyValue.Prompt,
                    ForcedBufferCopyPolicyValue =
                        QuicBufferCopyPolicyValue.MemoryConservative,
                }));

        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
                (QuicPacketFlushCadenceObservationMode)byte.MaxValue,
                forcedValue: null));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
                QuicPacketFlushCadenceObservationMode.Disabled,
                (QuicPacketFlushCadencePolicyValue)byte.MaxValue));
    }

    [Theory]
    [InlineData(
        (byte)QuicPacketFlushCadencePolicyValue.LegacyCurrent,
        true,
        false)]
    [InlineData(
        (byte)QuicPacketFlushCadencePolicyValue.Prompt,
        false,
        true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeForcesEachValueAtTheExistingPacketBoundary(
        byte forcedValue,
        bool expectDelayTimer,
        bool expectDatagram)
    {
        RecordingPacketFlushSink sink = new();
        await using QuicConnectionRuntime runtime =
            CreateRuntime(
                (QuicPacketFlushCadencePolicyValue)forcedValue,
                QuicPacketFlushCadenceObservationMode.ObserveOnly,
                sink,
                out Queue<PostedStreamWrite> postedWrites,
                out QuicStreamId streamId);

        Task write = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[16]).AsTask();
        QuicConnectionTransitionResult result =
            TransitionNext(runtime, postedWrites);
        await write.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(
            expectDelayTimer,
            runtime.TimerState.GetDueTicks(
                QuicConnectionTimerKind.ApplicationSendDelay).HasValue);
        Assert.Equal(
            expectDatagram,
            result.Effects.OfType<QuicConnectionSendDatagramEffect>().Any());
        QuicPacketFlushCadenceObservation observation =
            Assert.Single(sink.Observations);
        Assert.Equal(
            (QuicPacketFlushCadencePolicyValue)forcedValue,
            observation.ForcedValue);
        Assert.Equal(
            (QuicPacketFlushCadencePolicyValue)forcedValue,
            observation.AppliedValue);
        Assert.Equal(expectDelayTimer, observation.DelayApplied);
        Assert.Equal(expectDatagram, observation.PromptFlushApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeShadowDoesNotChangeTheLegacyDelay()
    {
        RecordingPacketFlushSink sink = new();
        await using QuicConnectionRuntime runtime =
            CreateRuntime(
                forcedValue: null,
                QuicPacketFlushCadenceObservationMode.Shadow,
                sink,
                out Queue<PostedStreamWrite> postedWrites,
                out QuicStreamId streamId);

        Task write = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[16]).AsTask();
        QuicConnectionTransitionResult result =
            TransitionNext(runtime, postedWrites);
        await write.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Empty(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.NotNull(runtime.TimerState.GetDueTicks(
            QuicConnectionTimerKind.ApplicationSendDelay));
        QuicPacketFlushCadenceObservation observation =
            Assert.Single(sink.Observations);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.Prompt,
            observation.SelectedValue);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            observation.AppliedValue);
        Assert.True(observation.DelayApplied);
        Assert.False(observation.PromptFlushApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task EvidenceSinkFailureCannotEscapeOrChangePromptSend()
    {
        await using QuicConnectionRuntime runtime =
            CreateRuntime(
                QuicPacketFlushCadencePolicyValue.Prompt,
                QuicPacketFlushCadenceObservationMode.ObserveOnly,
                new ThrowingPacketFlushSink(),
                out Queue<PostedStreamWrite> postedWrites,
                out QuicStreamId streamId);

        Task write = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[16]).AsTask();
        QuicConnectionTransitionResult result =
            TransitionNext(runtime, postedWrites);

        await write.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Single(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Null(runtime.TimerState.GetDueTicks(
            QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ConfiguredEpochSnapshotExistsWithoutAnEligibleWrite()
    {
        QuicPacketFlushCadenceConfiguredPolicySnapshot snapshot =
            QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
                QuicPacketFlushCadenceObservationMode.Shadow,
                forcedValue: null);
        QuicPacketFlushCadenceEpochAccumulator accumulator =
            new(in snapshot);

        QuicPacketFlushCadenceEpochSummary summary =
            accumulator.CaptureAndReset();

        Assert.False(summary.HasObservation);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.Prompt,
            summary.PolicySnapshot.SelectedValue);
        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            summary.PolicySnapshot.AppliedValue);
        Assert.Equal(
            QuicPacketFlushCadenceLatchLifetime
                .LogicalWritePacketOpportunity,
            summary.PolicySnapshot.LatchLifetime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ObservationAndEpochPassTheirVersionedSchemas()
    {
        QuicPacketFlushCadenceConfiguredPolicySnapshot snapshot =
            QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
                QuicPacketFlushCadenceObservationMode.ObserveOnly,
                QuicPacketFlushCadencePolicyValue.Prompt);
        QuicPacketFlushCadenceObservation observation = new(
            OperationSequence: 1,
            RequestId: 1,
            QuicPacketFlushCadenceObservationMode.ObserveOnly,
            QuicPacketFlushCadencePolicyValue.Prompt,
            ShadowRecommendation: null,
            QuicPacketFlushCadencePolicyValue.Prompt,
            QuicPacketFlushCadencePolicyValue.Prompt,
            QuicPacketFlushCadenceSelectionSource.Forced,
            QuicPacketFlushCadenceReasonCode.PromptFlush,
            QuicPacketFlushCadenceSafetyOverride.None,
            QuicPacketFlushCadenceDecisionBoundary
                .AuthorizedApplicationPacketConstruction,
            QuicPacketFlushCadenceLatchLifetime
                .LogicalWritePacketOpportunity,
            FallbackApplied: false,
            LegacyDelayEligible: true,
            DelayApplied: false,
            PromptFlushApplied: true,
            StreamPayloadLength: 16,
            QueuedWriteCount: 0,
            FinishWrites: false,
            AddressValidated: true,
            RetransmissionPending: false,
            QuicConnectionPhase.Active,
            DisposalStarted: false,
            QuicPacketFlushCadenceValidity.None);
        QuicPacketFlushCadenceEpochAccumulator accumulator =
            new(in snapshot);
        Assert.True(accumulator.TryPublish(in observation));
        QuicPacketFlushCadenceEpochSummary epoch =
            accumulator.CaptureAndReset();

        string repoRoot =
            AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"packet-flush-schema-test-{Guid.NewGuid():N}");
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
                            "quic-packet-flush-cadence-raw-v1",
                        connectionKey = "connection-0001",
                        observation,
                    },
                    jsonOptions));

            string schemas = Path.Combine(repoRoot, "schemas");
            string command =
                $"$observationValid = Get-Content -LiteralPath {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(observationPath)} -Raw | Test-Json -SchemaFile {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(Path.Combine(schemas, "adaptive-runtime-packet-flush-cadence-observation-v1.schema.json"))}; "
                + $"$epochValid = Get-Content -LiteralPath {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(epochPath)} -Raw | Test-Json -SchemaFile {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(Path.Combine(schemas, "adaptive-runtime-packet-flush-cadence-epoch-v1.schema.json"))}; "
                + $"$rawValid = Get-Content -LiteralPath {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(rawPath)} -Raw | Test-Json -SchemaFile {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(Path.Combine(schemas, "adaptive-runtime-packet-flush-cadence-raw-v1.schema.json"))}; "
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
    public void ListenerOptionCopyPreservesPacketFlushForceAndEvidence()
    {
        RecordingPacketFlushSink sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            ForcedPacketFlushCadencePolicyValue =
                QuicPacketFlushCadencePolicyValue.Prompt,
            PacketFlushCadenceObservationMode =
                QuicPacketFlushCadenceObservationMode.Shadow,
            PacketFlushCadenceEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(
            selectedOptions,
            returnedOptions);

        Assert.Equal(
            QuicPacketFlushCadencePolicyValue.Prompt,
            selectedOptions.ForcedPacketFlushCadencePolicyValue);
        Assert.Equal(
            QuicPacketFlushCadenceObservationMode.Shadow,
            selectedOptions.PacketFlushCadenceObservationMode);
        Assert.Same(sink, selectedOptions.PacketFlushCadenceEvidenceSink);
    }

    private static QuicConnectionRuntime CreateRuntime(
        QuicPacketFlushCadencePolicyValue? forcedValue,
        QuicPacketFlushCadenceObservationMode observationMode,
        IQuicPacketFlushCadenceEvidenceSink sink,
        out Queue<PostedStreamWrite> postedWrites,
        out QuicStreamId streamId)
    {
        QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath(
                    connectionSendLimit: 4_096,
                    localBidirectionalSendLimit: 4_096);
        postedWrites = new();
        Queue<PostedStreamWrite> capturedWrites = postedWrites;
        runtime.SetStreamWriteDispatcher(
            (requestId, actionKind, id, streamData, streamDataSuffix) =>
            {
                capturedWrites.Enqueue(new(
                    requestId,
                    actionKind,
                    id,
                    streamData,
                    streamDataSuffix));
                return true;
            });
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ForcedPacketFlushCadencePolicyValue = forcedValue,
                PacketFlushCadenceObservationMode = observationMode,
                PacketFlushCadenceEvidenceSink = sink,
            });
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out streamId,
            out _));
        return runtime;
    }

    private static QuicConnectionTransitionResult TransitionNext(
        QuicConnectionRuntime runtime,
        Queue<PostedStreamWrite> postedWrites)
    {
        PostedStreamWrite posted = postedWrites.Dequeue();
        return runtime.TransitionStreamWrite(
            posted.RequestId,
            posted.ActionKind,
            posted.StreamId,
            posted.StreamData,
            posted.StreamDataSuffix,
            nowTicks: 20);
    }

    private readonly record struct PostedStreamWrite(
        long RequestId,
        QuicConnectionStreamActionKind ActionKind,
        ulong StreamId,
        ReadOnlyMemory<byte> StreamData,
        ReadOnlyMemory<byte> StreamDataSuffix);

    private sealed class RecordingPacketFlushSink :
        IQuicPacketFlushCadenceEvidenceSink
    {
        internal List<QuicPacketFlushCadenceObservation> Observations
        {
            get;
        } = [];

        public bool TryPublish(
            in QuicPacketFlushCadenceObservation observation)
        {
            Observations.Add(observation);
            return true;
        }
    }

    private sealed class ThrowingPacketFlushSink :
        IQuicPacketFlushCadenceEvidenceSink
    {
        public bool TryPublish(
            in QuicPacketFlushCadenceObservation observation)
            => throw new InvalidOperationException("diagnostic sink failure");
    }
}

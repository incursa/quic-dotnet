// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0176")]
public sealed class REQ_QUIC_CRT_0176
{
    [Theory]
    [InlineData((int)QuicApplicationSendTurnSignalMask.QueuedApplicationWrites)]
    [InlineData((int)QuicApplicationSendTurnSignalMask.Congestion)]
    [InlineData((int)QuicApplicationSendTurnSignalMask.Lifecycle)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MissingRequiredSignalRecommendsConservativeFallback(int missingSignal)
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                MissingSignalMask = (QuicApplicationSendTurnSignalMask)missingSignal,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicApplicationSendTurnShadowReason.MissingSignal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StaleRequiredSignalRecommendsConservativeFallback()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                StaleSignalMask = QuicApplicationSendTurnSignalMask.ActorServiceTimeEwma,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicApplicationSendTurnShadowReason.StaleSignal);
    }

    [Theory]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.ArithmeticSaturated,
        (int)QuicApplicationSendTurnShadowReason.ArithmeticSaturated)]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.Contradictory,
        (int)QuicApplicationSendTurnShadowReason.ContradictorySignals)]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.OutOfDomain,
        (int)QuicApplicationSendTurnShadowReason.OutOfDomain)]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.RecoveryUnstable,
        (int)QuicApplicationSendTurnShadowReason.RecoveryGuard)]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.ResourceConstrained,
        (int)QuicApplicationSendTurnShadowReason.ResourceGuard)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BoundedGuardFlagsHaveDeterministicReasons(int flagsValue, int reasonValue)
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                Conditions = (QuicApplicationSendTurnObservationCondition)flagsValue,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, (QuicApplicationSendTurnShadowReason)reasonValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void FallbackReasonPrecedenceIsStable()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                MissingSignalMask = QuicApplicationSendTurnSignalMask.Congestion,
                StaleSignalMask = QuicApplicationSendTurnSignalMask.Lifecycle,
                Conditions = QuicApplicationSendTurnObservationCondition.ArithmeticSaturated
                    | QuicApplicationSendTurnObservationCondition.RecoveryUnstable,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicApplicationSendTurnShadowReason.MissingSignal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void VersionMismatchRecommendsConservativeFallback()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                PolicyRuleVersion = "unreviewed-rule",
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicApplicationSendTurnShadowReason.RuleVersionMismatch);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DuplicateAndOutOfOrderTurnsAreRejected()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation first =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 2);
        Assert.True(controller.TryEvaluate(in first, out QuicApplicationSendTurnPolicySnapshot firstSnapshot));

        Assert.False(controller.TryEvaluate(in first, out _));
        QuicApplicationSendTurnObservation earlier =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1);
        Assert.False(controller.TryEvaluate(in earlier, out _));

        QuicApplicationSendTurnObservation next =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 3);
        Assert.True(controller.TryEvaluate(in next, out QuicApplicationSendTurnPolicySnapshot nextSnapshot));
        Assert.Equal(firstSnapshot.SnapshotSequence + 1, nextSnapshot.SnapshotSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void IdenticalOrderedObservationsReplayIdentically()
    {
        QuicApplicationSendTurnShadowController first = default;
        QuicApplicationSendTurnShadowController second = default;
        QuicApplicationSendTurnObservation[] observations =
        [
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1),
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 2) with
            {
                Conditions = QuicApplicationSendTurnObservationCondition.ResourceConstrained,
            },
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 3),
        ];

        foreach (QuicApplicationSendTurnObservation observation in observations)
        {
            Assert.True(first.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot firstSnapshot));
            Assert.True(second.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot secondSnapshot));
            Assert.Equal(firstSnapshot, secondSnapshot);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TerminalStateCannotReturnToLegacyState()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation terminal =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                LifecycleFlags = QuicAdaptiveRuntimeLifecycle.Closing
                    | QuicAdaptiveRuntimeLifecycle.Terminal,
            };
        Assert.True(controller.TryEvaluate(in terminal, out QuicApplicationSendTurnPolicySnapshot terminalSnapshot));
        Assert.Equal(QuicApplicationSendTurnShadowState.Terminal, terminalSnapshot.State);

        QuicApplicationSendTurnObservation active =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 2);
        Assert.True(controller.TryEvaluate(in active, out QuicApplicationSendTurnPolicySnapshot laterSnapshot));
        Assert.Equal(QuicApplicationSendTurnShadowState.Terminal, laterSnapshot.State);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.Conservative, laterSnapshot.RecommendedPolicy);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeInputContractExcludesWorkloadAndIdentityLabels()
    {
        string[] forbiddenNames =
        [
            "Scenario",
            "Workload",
            "PayloadConstant",
            "RequestedConcurrency",
            "PeerIdentity",
            "Url",
            "ApplicationIdentity",
        ];
        string[] propertyNames = typeof(QuicApplicationSendTurnObservation)
            .GetProperties()
            .Select(static property => property.Name)
            .ToArray();

        foreach (string forbiddenName in forbiddenNames)
        {
            Assert.DoesNotContain(forbiddenName, propertyNames, StringComparer.OrdinalIgnoreCase);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RawHostKeepsShadowEvidenceSeparateFromForcedConstructionProvenance()
    {
        string source = File.ReadAllText(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "eng/protocol-lab/servers/IncursaRawQuicServer/Program.cs"));

        Assert.Contains(
            "adaptive-runtime-application-send-turn-provenance-v1",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "adaptive-runtime-application-send-turn-raw-v1",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "QUIC_APPLICATION_SEND_TURN_POLICY_JSON=",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "QUIC_APPLICATION_SEND_TURN_EVIDENCE_JSON=",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "IQuicApplicationSendTurnEvidenceSink",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "evidence.HasRecommendation ? evidence.Snapshot : null",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "Only one adaptive-runtime policy axis can be forced or observed",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "? QuicReceiveCreditPolicyMode.LegacyCurrent",
            source,
            StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void QueueObservationStopsAtTheReviewedBoundAndMarksPartialEvidence()
    {
        QuicApplicationSendQueue queue = new();
        for (int index = 0; index < 65; index++)
        {
            queue.EnqueueRawStreamData(
                streamId: (ulong)index,
                priority: 0,
                streamData: new byte[8],
                streamDataLength: 4,
                streamOffset: 0,
                isFinal: false,
                firstEnqueuedAtMicros: (ulong)(100 + index));
        }

        QuicApplicationSendTurnQueueSnapshot snapshot = queue.CaptureBoundedTurnSnapshot(
            nowMicros: 1_000,
            maximumObservedWrites: 64,
            maximumObservedDistinctStreams: 12);

        Assert.False(snapshot.Complete);
        Assert.Equal(65U, snapshot.QueuedApplicationWrites);
        Assert.Equal(65U, snapshot.RetainedSendBuffers);
        Assert.Equal(256UL, snapshot.OutboundBacklogBytes);
        Assert.Equal(512UL, snapshot.RetainedSendBytes);
        Assert.Equal(12, snapshot.DistinctQueuedStreams);
        Assert.Equal(900UL, snapshot.OldestQueuedSendAgeMicros);
    }

    [Theory]
    [InlineData((int)QuicApplicationSendTurnObservationMode.Disabled, true)]
    [InlineData((int)QuicApplicationSendTurnObservationMode.Shadow, false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EvidenceSinkConfigurationMustMatchTheObservationMode(
        int modeValue,
        bool includeSink)
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            ApplicationSendTurnObservationMode =
                (QuicApplicationSendTurnObservationMode)modeValue,
            ApplicationSendTurnEvidenceSink = includeSink
                ? new RecordingEvidenceSink()
                : null,
        };

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicApplicationSendTurnObservationMode.Disabled,
            runtime.ApplicationSendTurnObservationMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UndefinedObservationModeIsRejectedWithoutPartialConfiguration()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            ApplicationSendTurnObservationMode = (QuicApplicationSendTurnObservationMode)byte.MaxValue,
            ApplicationSendTurnEvidenceSink = new RecordingEvidenceSink(),
        };

        Assert.Throws<ArgumentOutOfRangeException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicApplicationSendTurnObservationMode.Disabled,
            runtime.ApplicationSendTurnObservationMode);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionCopyPreservesAxisSpecificModeAndSink()
    {
        RecordingEvidenceSink sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            ApplicationSendTurnObservationMode =
                QuicApplicationSendTurnObservationMode.ObserveOnly,
            ApplicationSendTurnEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(selectedOptions, returnedOptions);

        Assert.Equal(
            QuicApplicationSendTurnObservationMode.ObserveOnly,
            selectedOptions.ApplicationSendTurnObservationMode);
        Assert.Same(sink, selectedOptions.ApplicationSendTurnEvidenceSink);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackRestoresTheDisabledNullPlannerBaseline()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode = QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendTurnPolicyMode = QuicApplicationSendTurnPolicyMode.LegacyCurrent,
        });

        Assert.Equal(
            QuicApplicationSendTurnObservationMode.Disabled,
            runtime.ApplicationSendTurnObservationMode);
        Assert.Equal(
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            runtime.ApplicationSendTurnPolicyMode);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void SteadyStateEvaluationDoesNotAllocate()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation warmup =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1);
        Assert.True(controller.TryEvaluate(in warmup, out _));

        bool allEvaluated = true;
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (ulong turnSequence = 2; turnSequence < 1026; turnSequence++)
        {
            QuicApplicationSendTurnObservation observation =
                QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence);
            allEvaluated &= controller.TryEvaluate(in observation, out _);
        }

        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.True(allEvaluated);
        Assert.Equal(allocatedBefore, allocatedAfter);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SendTurnEvidenceExporterEmitsVersionedEpochRowsAndRetainsChecksums()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"send-turn-epoch-export-{Guid.NewGuid():N}");
        string outputDirectory = Path.Combine(temporaryDirectory, "export");
        string rawEvidencePath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/application-send-turn-evidence.raw.example.jsonl");

        try
        {
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                RunSendTurnEvidenceExporter(rawEvidencePath, outputDirectory);

            Assert.Equal(0, result.ExitCode);
            string[] rowPaths = Directory.GetFiles(outputDirectory, "send-turn-row-*.json")
                .OrderBy(static path => path, StringComparer.Ordinal)
                .ToArray();
            Assert.Equal(2, rowPaths.Length);

            using JsonDocument firstRow = JsonDocument.Parse(File.ReadAllText(rowPaths[0]));
            using JsonDocument secondRow = JsonDocument.Parse(File.ReadAllText(rowPaths[1]));
            JsonElement first = firstRow.RootElement;
            JsonElement second = secondRow.RootElement;

            Assert.Equal("adaptive-runtime-policy-epoch-dataset-v1", first.GetProperty("schemaVersion").GetString());
            Assert.Equal(0, first.GetProperty("epochIndex").GetInt32());
            Assert.Equal(1_000, first.GetProperty("epochDurationMicros").GetInt64());
            Assert.Equal(
                JsonValueKind.Null,
                first.GetProperty("preDecisionObservations").GetProperty("hasIssuedApplicationData").ValueKind);
            Assert.Equal(
                131_072,
                first.GetProperty("preDecisionObservations").GetProperty("queueToServiceRatioQ16").GetInt64());
            Assert.Equal(
                "legacy_current",
                first.GetProperty("currentPolicyState").GetProperty("state").GetString());
            Assert.Equal(
                "legacy_current",
                first.GetProperty("candidatePolicySelection").GetProperty("selectedPolicy").GetString());
            Assert.Equal(
                "legacy_current",
                first.GetProperty("candidatePolicySelection").GetProperty("shadowRecommendation").GetString());
            Assert.Equal(
                ["none"],
                first.GetProperty("analysisExclusionFlags").EnumerateArray()
                    .Select(static value => value.GetString()!)
                    .ToArray());

            Assert.Equal(1, second.GetProperty("epochIndex").GetInt32());
            Assert.Equal(1, second.GetProperty("epochDurationMicros").GetInt64());
            Assert.Equal(
                "fallback",
                second.GetProperty("currentPolicyState").GetProperty("state").GetString());
            Assert.Equal(
                "conservative",
                second.GetProperty("candidatePolicySelection").GetProperty("shadowRecommendation").GetString());
            Assert.Equal(
                "resource_guard",
                second.GetProperty("transitionState").GetProperty("reasonCode").GetString());
            Assert.Contains(
                "terminal_partial_epoch",
                second.GetProperty("analysisExclusionFlags").EnumerateArray()
                    .Select(static value => value.GetString()));

            string sourceSha256 = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(rawEvidencePath)))
                .ToLowerInvariant();
            Assert.Equal(
                sourceSha256,
                first.GetProperty("provenance").GetProperty("sourceArtifactSha256").GetString());
            Assert.Equal(
                sourceSha256,
                second.GetProperty("provenance").GetProperty("sourceArtifactSha256").GetString());

            using JsonDocument manifest = JsonDocument.Parse(File.ReadAllText(
                Path.Combine(outputDirectory, "send-turn-epoch-export-manifest.json")));
            Assert.Equal(2, manifest.RootElement.GetProperty("rowCount").GetInt32());
            Assert.Equal(sourceSha256, manifest.RootElement.GetProperty("sourceArtifactSha256").GetString());
            Assert.Equal(2, manifest.RootElement.GetProperty("rowChecksums").GetArrayLength());
        }
        finally
        {
            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SendTurnEvidenceExporterKeepsObserveOnlyRowsRecommendationFree()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"send-turn-observe-only-export-{Guid.NewGuid():N}");
        string outputDirectory = Path.Combine(temporaryDirectory, "export");
        string rawEvidencePath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/application-send-turn-observe-only.raw.example.jsonl");

        try
        {
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                RunSendTurnEvidenceExporter(rawEvidencePath, outputDirectory);

            Assert.Equal(0, result.ExitCode);
            string rowPath = Assert.Single(Directory.GetFiles(outputDirectory, "send-turn-row-*.json"));
            using JsonDocument row = JsonDocument.Parse(File.ReadAllText(rowPath));
            JsonElement root = row.RootElement;
            JsonElement state = root.GetProperty("currentPolicyState");
            JsonElement selection = root.GetProperty("candidatePolicySelection");

            Assert.Equal("quiescent", state.GetProperty("state").GetString());
            Assert.Equal("legacy_current", state.GetProperty("appliedPolicy").GetString());
            Assert.Equal("legacy", selection.GetProperty("selectionSource").GetString());
            Assert.Equal("legacy_current", selection.GetProperty("selectedPolicy").GetString());
            Assert.Equal(JsonValueKind.Null, selection.GetProperty("shadowRecommendation").ValueKind);
            Assert.Equal("none", selection.GetProperty("reasonCode").GetString());
            Assert.Contains(
                "terminal_partial_epoch",
                root.GetProperty("analysisExclusionFlags").EnumerateArray()
                    .Select(static value => value.GetString()));
        }
        finally
        {
            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SendTurnEvidenceExporterRejectsDuplicateTurnsWithoutEmittingRows()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"send-turn-epoch-duplicate-{Guid.NewGuid():N}");
        string outputDirectory = Path.Combine(temporaryDirectory, "export");
        string rawEvidencePath = Path.Combine(temporaryDirectory, "duplicate.raw.jsonl");

        try
        {
            Directory.CreateDirectory(temporaryDirectory);
            string fixture = File.ReadAllText(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                "tests/fixtures/adaptive-runtime-policy/application-send-turn-evidence.raw.example.jsonl"));
            File.WriteAllText(
                rawEvidencePath,
                fixture.Replace("\"turnSequence\":2", "\"turnSequence\":1", StringComparison.Ordinal));

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                RunSendTurnEvidenceExporter(rawEvidencePath, outputDirectory);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("duplicate or out of order", result.Output, StringComparison.Ordinal);
            Assert.Empty(Directory.GetFiles(outputDirectory, "send-turn-row-*.json"));
        }
        finally
        {
            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }
    }

    private static AdaptiveRuntimePolicyScriptTestSupport.ProcessResult RunSendTurnEvidenceExporter(
        string rawEvidencePath,
        string outputDirectory)
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        return AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
            "eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnEvidence.ps1",
            "-RawEvidencePath", rawEvidencePath,
            "-OutputDirectory", outputDirectory,
            "-DatasetId", "send-turn-test-dataset",
            "-CampaignId", "send-turn-test-campaign",
            "-RunId", "send-turn-test-run",
            "-CellId", "send-turn-test-cell",
            "-SampleId", "send-turn-test-sample",
            "-BenchmarkSha256", new string('a', 64),
            "-RuntimeSha256", new string('b', 64),
            "-HostFingerprint", "test-host-fingerprint",
            "-CorrectnessFlagsJson",
            "{\"payloadValid\":true,\"protocolValid\":true,\"timedOut\":false,\"ownershipValid\":true,\"terminalValid\":true,\"violationCodes\":[]}",
            "-ScenarioId", "quic.transport.stream-throughput.1mb",
            "-TrafficShape", "upload",
            "-AccountingMode", "fixed_per_stream",
            "-ArrivalPattern", "sustained",
            "-PayloadBytes", "4096",
            "-Connections", "1",
            "-StreamsPerConnection", "4",
            "-WarmupMicros", "0",
            "-MeasurementMicros", "10000",
            "-MonotonicTimerFrequencyHz", "1000000",
            "-RepositoryRoot", repoRoot,
            "-RepositoryCommit", "0123456789abcdef0123456789abcdef01234567");
    }

    private static void AssertFallback(
        QuicApplicationSendTurnPolicySnapshot snapshot,
        QuicApplicationSendTurnShadowReason expectedReason)
    {
        Assert.Equal(QuicApplicationSendTurnShadowState.Fallback, snapshot.State);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.LegacyCurrent, snapshot.AppliedPolicy);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.Conservative, snapshot.RecommendedPolicy);
        Assert.Equal(expectedReason, snapshot.Reason);
    }

    private sealed class RecordingEvidenceSink : IQuicApplicationSendTurnEvidenceSink
    {
        public bool TryPublish(in QuicApplicationSendTurnEvidence evidence) => true;
    }
}

internal static class QuicApplicationSendTurnShadowTestSupport
{
    internal static QuicApplicationSendTurnObservation CreateObservation(ulong turnSequence)
        => new(
            turnSequence,
            CapturedAtTicks: checked((long)turnSequence),
            QuicApplicationSendTurnObservation.CurrentObservationContractVersion,
            QuicApplicationSendTurnObservation.CurrentPolicyRuleVersion,
            MissingSignalMask: QuicApplicationSendTurnSignalMask.None,
            StaleSignalMask: QuicApplicationSendTurnSignalMask.None,
            Conditions: QuicApplicationSendTurnObservationCondition.None,
            LifecycleFlags: QuicAdaptiveRuntimeLifecycle.Active,
            QueuedApplicationWrites: 4,
            OutboundBacklogBytes: 4_096,
            DistinctQueuedStreams: 4,
            OldestQueuedSendAgeMicros: 250,
            QueueDelayEwmaMicros: 100,
            ActorServiceTimeEwmaMicros: 50,
            BurstLimitHits: 0,
            BytesInFlight: 1_024,
            CongestionWindowBytes: 12_000,
            RetainedSendBuffers: 4,
            RetainedSendBytes: 4_096);
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

public sealed partial class REQ_QUIC_CRT_0177
{
    [Fact]
    public void ConfiguredPolicyMapsAllAxisModesAndRejectsMultipleTreatments()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot snapshot =
            QuicAdaptiveRuntimeStage1ConfiguredPolicy.Create(
                sendTurnForced: null,
                QuicApplicationSendTurnObservationMode.Shadow,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicApplicationSendBatchObservationMode.Shadow,
                burstForced: null,
                QuicQueuedSendBurstObservationMode.Shadow,
                oversizedForced: null,
                QuicOversizedWriteAdmissionObservationMode.Shadow);

        Assert.True(snapshot.ApplicationSendTurnPlanning.HasShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.ApplicationSendTurnPlanning.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            snapshot.ApplicationSendBatchFormation.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            snapshot.QueuedSendBurstBudget.ShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment,
            snapshot.OversizedWriteAdmissionQuantum.ShadowRecommendation);

        Assert.Throws<ArgumentException>(
            () => QuicAdaptiveRuntimeStage1ConfiguredPolicy.Create(
                QuicApplicationSendTurnPolicyMode.Conservative,
                QuicApplicationSendTurnObservationMode.Shadow,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicApplicationSendBatchObservationMode.Shadow,
                burstForced: null,
                QuicQueuedSendBurstObservationMode.Shadow,
                oversizedForced: null,
                QuicOversizedWriteAdmissionObservationMode.Shadow));
    }

    [Fact]
    public void OneForcedAxisCanObserveAllFourAxesOnOneConnection()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot configured =
            QuicAdaptiveRuntimeStage1ConfiguredPolicy.Create(
                sendTurnForced: null,
                QuicApplicationSendTurnObservationMode.Shadow,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicApplicationSendBatchObservationMode.Shadow,
                burstForced: null,
                QuicQueuedSendBurstObservationMode.Shadow,
                oversizedForced: null,
                QuicOversizedWriteAdmissionObservationMode.Shadow);
        QuicAdaptiveRuntimeStage1EvidenceAccumulator accumulator =
            new(in configured);
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());

        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendBatchPolicyMode =
                QuicApplicationSendBatchPolicyMode.SingleEligible,
            AdaptiveRuntimeShadowEnabled = true,
            AdaptiveRuntimeShadowEpochInterval = TimeSpan.FromMilliseconds(250),
            AdaptiveRuntimeShadowEpochSink = new RecordingEpochSink(),
            ApplicationSendTurnObservationMode =
                QuicApplicationSendTurnObservationMode.Shadow,
            ApplicationSendTurnEvidenceSink = accumulator,
            ApplicationSendBatchObservationMode =
                QuicApplicationSendBatchObservationMode.Shadow,
            ApplicationSendBatchEvidenceSink = accumulator,
            QueuedSendBurstObservationMode =
                QuicQueuedSendBurstObservationMode.Shadow,
            QueuedSendBurstEvidenceSink = accumulator,
            OversizedWriteAdmissionObservationMode =
                QuicOversizedWriteAdmissionObservationMode.Shadow,
            OversizedWriteAdmissionEvidenceSink = accumulator,
        });

        Assert.Equal(
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            runtime.GetAppliedReceiveCreditPolicyMode());
        Assert.Equal(
            QuicApplicationSendTurnObservationMode.Shadow,
            runtime.ApplicationSendTurnObservationMode);
        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            runtime.ApplicationSendBatchPolicyMode);
        Assert.Equal(
            QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            runtime.QueuedSendBurstPolicyMode);
        Assert.Equal(
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            runtime.OversizedWriteAdmissionPolicyMode);
    }

    [Fact]
    public void ForcedSendTurnConstructionProvenanceRemainsSeparateFromUnifiedShadow()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot configured =
            QuicAdaptiveRuntimeStage1ConfiguredPolicy.Create(
                QuicApplicationSendTurnPolicyMode.Conservative,
                QuicApplicationSendTurnObservationMode.Shadow,
                sendBatchForced: null,
                QuicApplicationSendBatchObservationMode.Shadow,
                burstForced: null,
                QuicQueuedSendBurstObservationMode.Shadow,
                oversizedForced: null,
                QuicOversizedWriteAdmissionObservationMode.Shadow);
        QuicAdaptiveRuntimeStage1EvidenceAccumulator accumulator =
            new(in configured);
        RecordingProvenanceSink provenanceSink = new();
        using QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());

        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendTurnPolicyMode =
                QuicApplicationSendTurnPolicyMode.Conservative,
            ApplicationSendTurnPolicyProvenanceSink = provenanceSink,
            AdaptiveRuntimeShadowEnabled = true,
            AdaptiveRuntimeShadowEpochInterval = TimeSpan.FromMilliseconds(250),
            AdaptiveRuntimeShadowEpochSink = new RecordingEpochSink(),
            ApplicationSendTurnObservationMode =
                QuicApplicationSendTurnObservationMode.Shadow,
            ApplicationSendTurnEvidenceSink = accumulator,
            ApplicationSendBatchObservationMode =
                QuicApplicationSendBatchObservationMode.Shadow,
            ApplicationSendBatchEvidenceSink = accumulator,
            QueuedSendBurstObservationMode =
                QuicQueuedSendBurstObservationMode.Shadow,
            QueuedSendBurstEvidenceSink = accumulator,
            OversizedWriteAdmissionObservationMode =
                QuicOversizedWriteAdmissionObservationMode.Shadow,
            OversizedWriteAdmissionEvidenceSink = accumulator,
        });

        QuicApplicationSendTurnPolicyProvenance provenance =
            Assert.Single(provenanceSink.Evidence);
        Assert.Equal(
            QuicApplicationSendTurnPolicyMode.Conservative,
            provenance.AppliedPolicy);
        Assert.Equal(
            QuicApplicationSendTurnPolicyMode.Conservative,
            runtime.ApplicationSendTurnPolicyMode);
    }

    [Fact]
    public void EmptyEpochReportsAllFourAxesAsMissingWithoutInventingOperations()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot configured = new(
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning,
                shadow: true),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
                QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
                shadow: true),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget,
                shadow: true),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum,
                shadow: true));
        QuicAdaptiveRuntimeStage1EvidenceAccumulator accumulator =
            new(in configured);

        QuicAdaptiveRuntimeStage1EpochEvidence epoch =
            accumulator.CaptureEpoch(
                epochIndex: 1,
                epochStartOffsetMicros: 0,
                epochDurationMicros: 10_000);

        AssertMissing(epoch.ApplicationSendTurnPlanning);
        AssertMissing(epoch.ApplicationSendBatchFormation);
        AssertMissing(epoch.QueuedSendBurstBudget);
        AssertMissing(epoch.OversizedWriteAdmissionQuantum);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.Conservative,
            epoch.ApplicationSendTurnPlanning.Decision.SelectedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            epoch.ApplicationSendTurnPlanning.Decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            epoch.ApplicationSendBatchFormation.Decision.ForcedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            epoch.ApplicationSendBatchFormation.Decision.AppliedValue);
    }

    [Fact]
    public void EpochAccumulatorCombinesAllFourSinksAndResetsAtTheBoundary()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot configured = new(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
                QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum));
        QuicAdaptiveRuntimeStage1EvidenceAccumulator accumulator =
            new(in configured);

        QuicApplicationSendTurnObservation sendTurnObservation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 11);
        QuicApplicationSendTurnEvidence sendTurnEvidence = new(
            QuicApplicationSendTurnObservationMode.ObserveOnly,
            sendTurnObservation,
            HasRecommendation: false,
            Snapshot: default,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning));
        Assert.True(accumulator.TryPublish(in sendTurnEvidence));

        QuicApplicationSendBatchObservation sendBatchObservation =
            default(QuicApplicationSendBatchObservation) with
        {
            QueuedApplicationWrites = 3,
            OutboundBacklogBytes = 4096,
            DistinctQueuedStreams = 2,
            MaximumPayloadBytes = 1200,
            EligibleWriteCount = 3,
            EligibleWriteBytes = 1000,
        };
        QuicApplicationSendBatchEvidence sendBatchEvidence = new(
            QuicApplicationSendBatchObservationMode.ObserveOnly,
            sendBatchObservation,
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
                QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible),
            PlanKind: default,
            AppliedWriteCount: 1,
            HasMoreQueuedData: true,
            BlockedReason: default);
        Assert.True(accumulator.TryPublish(in sendBatchEvidence));

        QuicQueuedSendBurstObservation burstObservation =
            default(QuicQueuedSendBurstObservation) with
        {
            QueuedApplicationWrites = 4,
            OutboundBacklogBytes = 8192,
            DistinctQueuedStreams = 3,
            LegalMaximumDatagrams = 12,
            ConfiguredMaximumDatagrams = 12,
            HandshakeConfirmed = true,
        };
        QuicQueuedSendBurstEvidence burstEvidence = new(
            QuicQueuedSendBurstObservationMode.ObserveOnly,
            burstObservation,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            LegalMaximumDatagrams: 12,
            AppliedMaximumDatagrams: 12,
            EmittedDatagrams: 4,
            QueuedWritesBefore: 4,
            QueuedWritesAfter: 0,
            Outcome: default,
            BlockedReason: default);
        Assert.True(accumulator.TryPublish(in burstEvidence));

        QuicOversizedWriteAdmissionObservation oversizedObservation =
            default(QuicOversizedWriteAdmissionObservation) with
        {
            QueuedApplicationWrites = 1,
            DistinctObservedStreams = 1,
            LogicalRemainingBytes = 64 * 1024,
            MaximumApplicationPayloadBytes = 1200,
            MaximumFragmentBytes = 32 * 1024,
        };
        QuicOversizedWriteAdmissionEvidence oversizedEvidence = new(
            QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
            oversizedObservation,
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum),
            AppliedChunkQuantum: 1,
            CommittedFragments: 2,
            ContinuationPosts: 1,
            CommittedBytes: 64 * 1024,
            CompletionLatencyMicros: 500,
            QuicOversizedWriteOutcome.Completed);
        Assert.True(accumulator.TryPublish(in oversizedEvidence));

        QuicAdaptiveRuntimeStage1EpochEvidence epoch =
            accumulator.CaptureEpoch(
                epochIndex: 1,
                epochStartOffsetMicros: 0,
                epochDurationMicros: 10_000);

        Assert.True(epoch.ApplicationSendTurnPlanning.HasEvent);
        Assert.True(epoch.ApplicationSendBatchFormation.HasEvent);
        Assert.True(epoch.QueuedSendBurstBudget.HasEvent);
        Assert.True(epoch.OversizedWriteAdmissionQuantum.HasEvent);
        Assert.Equal(
            1UL,
            epoch.ApplicationSendBatchFormation.Outcomes.SelectedWriteCount);
        Assert.Equal(
            4UL,
            epoch.QueuedSendBurstBudget.Outcomes.EmittedDatagrams);
        Assert.Equal(
            2UL,
            epoch.OversizedWriteAdmissionQuantum.Outcomes.AdmittedFragments);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            epoch.PolicySnapshot.ApplicationSendBatchFormation.AppliedValue);

        QuicAdaptiveRuntimeStage1EpochEvidence nextEpoch =
            accumulator.CaptureEpoch(
                epochIndex: 2,
                epochStartOffsetMicros: 10_000,
                epochDurationMicros: 10_000);
        AssertMissing(nextEpoch.ApplicationSendTurnPlanning);
        AssertMissing(nextEpoch.ApplicationSendBatchFormation);
        AssertMissing(nextEpoch.QueuedSendBurstBudget);
        AssertMissing(nextEpoch.OversizedWriteAdmissionQuantum);
    }

    [Fact]
    public void EpochIndexesMustIncreaseAndDurationsMustBePositive()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot configured = new(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum));
        QuicAdaptiveRuntimeStage1EvidenceAccumulator accumulator =
            new(in configured);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => accumulator.CaptureEpoch(1, 0, 0));
        _ = accumulator.CaptureEpoch(1, 0, 1);
        Assert.Throws<InvalidOperationException>(
            () => accumulator.CaptureEpoch(1, 1, 1));
    }

    [Fact]
    public void RawUnifiedEpochSerializationPassesSchemaAndSemanticValidation()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"stage1-raw-validator-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            string json = CreateSerializedRawEpoch();
            string rawPath = Path.Combine(temporaryDirectory, "raw-epoch.json");
            File.WriteAllText(rawPath, json);

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimeStage1RawEvidence.ps1",
                    "-RawEpochPath",
                    rawPath);

            Assert.True(result.ExitCode == 0, result.Output);
            using JsonDocument summary = JsonDocument.Parse(result.Output);
            Assert.True(summary.RootElement.GetProperty("valid").GetBoolean());
            Assert.Equal(
                1,
                summary.RootElement.GetProperty("rawEpochRowCount").GetInt32());
            Assert.Equal(
                4,
                summary.RootElement.GetProperty("axisRecordCount").GetInt32());
            Assert.Equal(
                4,
                summary.RootElement.GetProperty("missingEventAxisCount").GetInt32());
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Fact]
    public void PermanentRawExporterPreservesHostLogsAndCreatesValidatedManifest()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"stage1-raw-exporter-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            string hostLogPath = Path.Combine(temporaryDirectory, "host.stdout.log");
            File.WriteAllLines(
                hostLogPath,
                [
                    "QUIC_ENDPOINT=127.0.0.1:4433",
                    "QUIC_ADAPTIVE_RUNTIME_STAGE1_UNIFIED_EPOCH_JSON="
                        + CreateSerializedRawEpoch(),
                ]);
            string outputDirectory = Path.Combine(temporaryDirectory, "export");

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Export-AdaptiveRuntimeStage1RawEpochs.ps1",
                    "-HostLogPath",
                    hostLogPath,
                    "-OutputDirectory",
                    outputDirectory);

            Assert.True(result.ExitCode == 0, result.Output);
            using JsonDocument summary = JsonDocument.Parse(result.Output);
            Assert.Equal(
                1,
                summary.RootElement.GetProperty("rowCount").GetInt32());
            Assert.Equal(
                4,
                summary.RootElement.GetProperty("axisRecordCount").GetInt32());
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "stage1-unified-raw-epochs.jsonl")));
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "raw-validation-summary.json")));
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "raw-export-manifest.json")));

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult second =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Export-AdaptiveRuntimeStage1RawEpochs.ps1",
                    "-HostLogPath",
                    hostLogPath,
                    "-OutputDirectory",
                    outputDirectory);
            Assert.NotEqual(0, second.ExitCode);
            Assert.Contains(
                "Append-only output path already exists",
                second.Output,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Fact]
    public void PermanentUnifiedMaterializerJoinsRawEpochsToSampleProvenance()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"stage1-unified-materializer-test-{Guid.NewGuid():N}");
        string sampleId = "sample-001";
        string sampleDirectory = Path.Combine(temporaryDirectory, sampleId);
        Directory.CreateDirectory(sampleDirectory);

        try
        {
            string hostLogPath = Path.Combine(
                sampleDirectory,
                "host.stdout.log");
            File.WriteAllLines(
                hostLogPath,
                [
                    "QUIC_ADAPTIVE_RUNTIME_STAGE1_UNIFIED_EPOCH_JSON="
                        + CreateSerializedRawEpoch(),
                ]);
            string exportDirectory = Path.Combine(
                temporaryDirectory,
                "raw-export");
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult export =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Export-AdaptiveRuntimeStage1RawEpochs.ps1",
                    "-HostLogPath",
                    hostLogPath,
                    "-OutputDirectory",
                    exportDirectory);
            Assert.True(export.ExitCode == 0, export.Output);

            string localResultPath = Path.Combine(
                temporaryDirectory,
                "local-result.json");
            File.WriteAllText(
                localResultPath,
                JsonSerializer.Serialize(
                    new
                    {
                        schemaVersion =
                            "adaptive-runtime-policy-local-result-v1",
                        campaignId = "stage1-unified-materializer-test",
                        runId = "stage1-unified-materializer-test-run",
                        cellId = "correctness-smoke",
                        classification = "diagnostic",
                        repositoryIdentities = new[]
                        {
                            new
                            {
                                name = "quic-dotnet",
                                commit = new string('a', 40),
                            },
                        },
                        binaryProvenance = new
                        {
                            assemblies = new[]
                            {
                                new
                                {
                                    role = "candidate_benchmark",
                                    sha256 = new string('b', 64),
                                },
                                new
                                {
                                    role = "candidate_runtime",
                                    sha256 = new string('c', 64),
                                },
                            },
                        },
                        environment = new
                        {
                            hostFingerprint = "test-host-fingerprint",
                        },
                        workload = new
                        {
                            scenarioId = "analysis-only-test-scenario",
                            trafficShape = "duplex",
                            payloadBytes = 65_536,
                            concurrency = 1,
                            effectiveConcurrency = 1,
                        },
                        samples = new[]
                        {
                            new
                            {
                                sampleId,
                                correctness = new
                                {
                                    payloadValidated = true,
                                    protocolErrors = 0,
                                    timedOutOperations = 0,
                                    failedOperations = 0,
                                    cancellationFailures = 0,
                                    disposalFailures = 0,
                                    invariantViolations =
                                        Array.Empty<string>(),
                                },
                            },
                        },
                    }));

            string materializedDirectory = Path.Combine(
                temporaryDirectory,
                "materialized");
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult materialized =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Convert-AdaptiveRuntimeStage1UnifiedEpochs.ps1",
                    "-RawEpochPath",
                    Path.Combine(
                        exportDirectory,
                        "stage1-unified-raw-epochs.jsonl"),
                    "-RawExportManifestPath",
                    Path.Combine(
                        exportDirectory,
                        "raw-export-manifest.json"),
                    "-LocalResultPath",
                    localResultPath,
                    "-OutputDirectory",
                    materializedDirectory);

            Assert.True(materialized.ExitCode == 0, materialized.Output);
            using JsonDocument summary = JsonDocument.Parse(
                materialized.Output);
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("unifiedEpochRowCount")
                    .GetInt32());
            Assert.Equal(
                4,
                summary.RootElement
                    .GetProperty("axisDecisionRowCount")
                    .GetInt32());
            Assert.True(
                summary.RootElement
                    .GetProperty("excludedFromPolicyAcceptance")
                    .GetBoolean());

            string unifiedPath = Path.Combine(
                materializedDirectory,
                "stage1-unified-epochs.jsonl");
            using JsonDocument unified = JsonDocument.Parse(
                File.ReadAllText(unifiedPath));
            Assert.Equal(
                sampleId,
                unified.RootElement.GetProperty("sampleId").GetString());
            Assert.Equal(
                4,
                unified.RootElement
                    .GetProperty("axisRecords")
                    .GetArrayLength());
            Assert.True(
                unified.RootElement
                    .GetProperty("workloadAnalysisOnly")
                    .GetProperty("excludedFromProductionFeatures")
                    .GetBoolean());

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult second =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Convert-AdaptiveRuntimeStage1UnifiedEpochs.ps1",
                    "-RawEpochPath",
                    Path.Combine(
                        exportDirectory,
                        "stage1-unified-raw-epochs.jsonl"),
                    "-RawExportManifestPath",
                    Path.Combine(
                        exportDirectory,
                        "raw-export-manifest.json"),
                    "-LocalResultPath",
                    localResultPath,
                    "-OutputDirectory",
                    materializedDirectory);
            Assert.NotEqual(0, second.ExitCode);
            Assert.Contains(
                "Append-only output path already exists",
                second.Output,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private static void AssertMissing(
        QuicAdaptiveRuntimeStage1EpochAxisRecord record)
    {
        Assert.False(record.HasEvent);
        Assert.Equal(0UL, record.EventCount);
        Assert.Equal(0UL, record.Outcomes.CompletedOperations);
        Assert.True(
            (record.Decision.Validity
                & QuicAdaptiveRuntimeStage1Validity.Missing) != 0);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1LatchState.Unlatched,
            record.Decision.LatchState);
        Assert.Equal(0UL, record.Decision.LatchSequence);
    }

    private static string CreateSerializedRawEpoch()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot configured =
            QuicAdaptiveRuntimeStage1ConfiguredPolicy.Create(
                sendTurnForced: null,
                QuicApplicationSendTurnObservationMode.Shadow,
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicApplicationSendBatchObservationMode.Shadow,
                burstForced: null,
                QuicQueuedSendBurstObservationMode.Shadow,
                oversizedForced: null,
                QuicOversizedWriteAdmissionObservationMode.Shadow);
        QuicAdaptiveRuntimeStage1EvidenceAccumulator accumulator =
            new(in configured);
        QuicAdaptiveRuntimeStage1EpochEvidence epoch =
            accumulator.CaptureEpoch(1, 0, 250_000);
        JsonSerializerOptions options =
            new(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return JsonSerializer.Serialize(
            new
            {
                schemaVersion =
                    "adaptive-runtime-stage1-unified-epoch-raw-v1",
                connectionKey = "connection-0001",
                epoch,
            },
            options);
    }

    private sealed class RecordingEpochSink : IQuicAdaptiveRuntimeShadowEpochSink
    {
        public bool TryPublish(
            in QuicAdaptiveRuntimeConnectionObservation observation,
            in QuicReceiveCreditPolicySnapshot snapshot)
            => true;
    }

    private sealed class RecordingProvenanceSink :
        IQuicApplicationSendTurnPolicyProvenanceSink
    {
        internal List<QuicApplicationSendTurnPolicyProvenance> Evidence { get; } = [];

        public bool TryPublish(in QuicApplicationSendTurnPolicyProvenance provenance)
        {
            Evidence.Add(provenance);
            return true;
        }
    }
}

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
            string json = JsonSerializer.Serialize(
                new
                {
                    schemaVersion =
                        "adaptive-runtime-stage1-unified-epoch-raw-v1",
                    connectionKey = "connection-0001",
                    epoch,
                },
                options);
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

    private sealed class RecordingEpochSink : IQuicAdaptiveRuntimeShadowEpochSink
    {
        public bool TryPublish(
            in QuicAdaptiveRuntimeConnectionObservation observation,
            in QuicReceiveCreditPolicySnapshot snapshot)
            => true;
    }
}

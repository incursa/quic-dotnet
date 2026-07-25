// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0183")]
public sealed class REQ_QUIC_CRT_0183
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HostedShardPublishesEpochAfterActorObservationAndResourceRelease()
    {
        FakeMonotonicClock clock = new(0);
        RecordingUnifiedSink sink = new();
        QuicAdaptiveRuntimeStage1PolicySnapshot configured =
            CreateDisabledStage1Policy();
        QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator accumulator =
            new(in configured, sink);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            AdaptiveRuntimeShadowEpochInterval =
                TimeSpan.FromMilliseconds(1),
            AdaptiveRuntimeShadowEpochSink = accumulator,
            ActorServiceObservationMode =
                QuicActorServiceObservationMode.ObserveOnly,
            ActorServiceEvidenceSink = accumulator,
        });
        await using QuicConnectionRuntimeShard shard = new(11, clock);
        Task consumer = shard.RunAsync();

        clock.Advance(Stopwatch.Frequency / 100);
        Assert.True(shard.TryPostFlowControlCreditUpdate(
            new QuicConnectionHandle(1),
            runtime));
        await sink.EpochPublished.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await shard.DisposeAsync();
        await consumer;

        QuicAdaptiveRuntimeUnifiedEpochEvidence evidence =
            Assert.Single(sink.Evidence);
        Assert.Equal(1UL, evidence.ActorService.ActorTurnCount);
        Assert.Equal(
            1UL,
            evidence.ConnectionObservation.ConnectionEpochSequence);
        Assert.Equal(
            evidence.ConnectionObservation.ConnectionEpochSequence,
            evidence.PostServiceBoundary.ConnectionEpochSequence);
        Assert.Equal(
            QuicAdaptiveRuntimePostServiceBoundarySource.HostedShard,
            evidence.PostServiceBoundary.Source);
        Assert.Equal(
            QuicActorServiceDisposition.Completed,
            evidence.PostServiceBoundary.Disposition);
        Assert.Equal(
            1UL,
            evidence.PostServiceBoundary.ActorServiceSequence);
        Assert.True(
            evidence.PostServiceBoundary.ActorObservationPublished);
        Assert.True(
            evidence.PostServiceBoundary.ResourceReleaseCompleted);
        Assert.Equal(
            QuicAdaptiveRuntimePostServiceBoundaryValidity.None,
            evidence.PostServiceBoundary.Validity);
        Assert.Equal(
            QuicAdaptiveRuntimePostServiceBoundary
                .CurrentBoundaryContractVersion,
            evidence.PostServiceBoundary.BoundaryContractVersion);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MissingActorObservationIsExplicitAtThePostServiceBoundary()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        RecordingPostServiceSink sink = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            AdaptiveRuntimeShadowEpochInterval =
                TimeSpan.FromMilliseconds(1),
            AdaptiveRuntimeShadowEpochSink = sink,
        });

        clock.Advance(Stopwatch.Frequency / 100);
        runtime.TryPublishReceiveCreditShadowAtPostServiceBoundary(
            clock.Ticks,
            QuicAdaptiveRuntimePostServiceBoundarySource.IndependentConsumer,
            QuicActorServiceDisposition.Completed,
            actorServiceSequence: null,
            actorObservationPublished: false,
            resourceReleaseCompleted: true);

        Assert.True(sink.EpochPublished.Task.IsCompletedSuccessfully);
        Assert.Null(sink.Boundary.ActorServiceSequence);
        Assert.False(sink.Boundary.ActorObservationPublished);
        Assert.True(sink.Boundary.ResourceReleaseCompleted);
        Assert.Equal(
            QuicAdaptiveRuntimePostServiceBoundaryValidity
                .ActorObservationUnavailable,
            sink.Boundary.Validity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FaultAndIncompleteReleaseRemainExplicitWithoutEscapingTheSink()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        RecordingPostServiceSink sink = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            AdaptiveRuntimeShadowEpochInterval =
                TimeSpan.FromMilliseconds(1),
            AdaptiveRuntimeShadowEpochSink = sink,
        });

        clock.Advance(Stopwatch.Frequency / 100);
        runtime.TryPublishReceiveCreditShadowAtPostServiceBoundary(
            clock.Ticks,
            QuicAdaptiveRuntimePostServiceBoundarySource.HostedShard,
            QuicActorServiceDisposition.Faulted,
            actorServiceSequence: 8,
            actorObservationPublished: false,
            resourceReleaseCompleted: false);

        Assert.Equal(
            QuicAdaptiveRuntimePostServiceBoundaryValidity
                .ActorObservationUnavailable
            | QuicAdaptiveRuntimePostServiceBoundaryValidity
                .ResourceReleaseIncomplete
            | QuicAdaptiveRuntimePostServiceBoundaryValidity.FaultedService,
            sink.Boundary.Validity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnifiedAccumulatorSealsStage1AndStage2AtTheSameJoinKey()
    {
        RecordingUnifiedSink sink = new();
        QuicAdaptiveRuntimeStage1PolicySnapshot configured =
            CreateLegacyStage1Policy();
        QuicBufferCopyConfiguredPolicySnapshot configuredBufferCopy =
            QuicBufferCopyPolicy.CreateConfiguredSnapshot(
                QuicBufferCopyObservationMode.ObserveOnly,
                forcedValue: null);
        QuicAdaptiveBackpressureConfiguredPolicySnapshot
            configuredAdaptiveBackpressure =
                QuicAdaptiveBackpressurePolicy.CreateConfiguredSnapshot(
                    QuicAdaptiveBackpressureObservationMode.ObserveOnly,
                    forcedValue: null);
        QuicPacketFlushCadenceConfiguredPolicySnapshot
            configuredPacketFlushCadence =
                QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
                    QuicPacketFlushCadenceObservationMode.ObserveOnly,
                    forcedValue: null);
        QuicReceiveDeliveryQuantumConfiguredPolicySnapshot
            configuredReceiveDeliveryQuantum =
                QuicReceiveDeliveryQuantumPolicy.CreateConfiguredSnapshot(
                    QuicReceiveDeliveryQuantumObservationMode.ObserveOnly,
                    forcedValue: null);
        QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator accumulator =
            new(
                in configured,
                in configuredBufferCopy,
                in configuredAdaptiveBackpressure,
                in configuredPacketFlushCadence,
                in configuredReceiveDeliveryQuantum,
                sink);
        QuicActorServiceObservation actor = CreateActorObservation();
        QuicBufferCopyObservation buffer = CreateBufferObservation();
        QuicAdaptiveBackpressureObservation adaptiveBackpressure =
            CreateAdaptiveBackpressureObservation();
        QuicPacketFlushCadenceObservation packetFlushCadence =
            CreatePacketFlushCadenceObservation();
        QuicReceiveDeliveryQuantumObservation receiveDeliveryQuantum =
            CreateReceiveDeliveryQuantumObservation();
        QuicAdaptiveRuntimeConnectionObservation connection =
            CreateConnectionObservation(epochSequence: 1);
        QuicReceiveCreditPolicySnapshot receiveCredit =
            CreateReceiveCreditSnapshot(epochSequence: 1);
        QuicAdaptiveRuntimePostServiceBoundary boundary =
            CreateBoundary(epochSequence: 1);

        Assert.True(accumulator.TryPublish(in actor));
        Assert.True(accumulator.TryPublish(in buffer));
        Assert.True(accumulator.TryPublish(in adaptiveBackpressure));
        Assert.True(accumulator.TryPublish(in packetFlushCadence));
        Assert.True(accumulator.TryPublish(in receiveDeliveryQuantum));
        Assert.True(accumulator.TryPublish(
            in connection,
            in receiveCredit,
            in boundary));

        QuicAdaptiveRuntimeUnifiedEpochEvidence evidence =
            Assert.Single(sink.Evidence);
        Assert.Equal(1UL, evidence.ConnectionEpochSequence);
        Assert.Equal(
            evidence.ConnectionEpochSequence,
            evidence.Stage1.EpochIndex);
        Assert.Equal(
            evidence.ConnectionEpochSequence,
            evidence.PostServiceBoundary.ConnectionEpochSequence);
        Assert.Equal(1UL, evidence.ActorService.ActorTurnCount);
        Assert.Equal(1UL, evidence.BufferCopy.OperationCount);
        Assert.False(evidence.Stage1.ApplicationSendTurnPlanning.HasEvent);
        Assert.Equal(
            QuicAdaptiveRuntimeUnifiedEpochEvidence
                .CurrentEvidenceContractVersion,
            evidence.EvidenceContractVersion);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidJoinIsRejectedBeforeAnyAccumulatorIsReset()
    {
        RecordingUnifiedSink sink = new();
        QuicAdaptiveRuntimeStage1PolicySnapshot configured =
            CreateLegacyStage1Policy();
        QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator accumulator =
            new(in configured, sink);
        QuicActorServiceObservation actor = CreateActorObservation();
        QuicAdaptiveRuntimeConnectionObservation connection =
            CreateConnectionObservation(epochSequence: 1);
        QuicReceiveCreditPolicySnapshot receiveCredit =
            CreateReceiveCreditSnapshot(epochSequence: 1);
        QuicAdaptiveRuntimePostServiceBoundary wrongBoundary =
            CreateBoundary(epochSequence: 2);
        QuicAdaptiveRuntimePostServiceBoundary correctBoundary =
            CreateBoundary(epochSequence: 1);

        Assert.True(accumulator.TryPublish(in actor));
        Assert.False(accumulator.TryPublish(
            in connection,
            in receiveCredit,
            in wrongBoundary));
        Assert.True(accumulator.TryPublish(
            in connection,
            in receiveCredit,
            in correctBoundary));

        QuicAdaptiveRuntimeUnifiedEpochEvidence evidence =
            Assert.Single(sink.Evidence);
        Assert.Equal(1UL, evidence.ActorService.ActorTurnCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BoundaryAndUnifiedEvidencePassVersionedSchemas()
    {
        RecordingUnifiedSink sink = new();
        QuicAdaptiveRuntimeStage1PolicySnapshot configured =
            CreateLegacyStage1Policy();
        QuicBufferCopyConfiguredPolicySnapshot configuredBufferCopy =
            QuicBufferCopyPolicy.CreateConfiguredSnapshot(
                QuicBufferCopyObservationMode.ObserveOnly,
                forcedValue: null);
        QuicAdaptiveBackpressureConfiguredPolicySnapshot
            configuredAdaptiveBackpressure =
                QuicAdaptiveBackpressurePolicy.CreateConfiguredSnapshot(
                    QuicAdaptiveBackpressureObservationMode.ObserveOnly,
                    forcedValue: null);
        QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator accumulator =
            new(
                in configured,
                in configuredBufferCopy,
                in configuredAdaptiveBackpressure,
                sink);
        QuicActorServiceObservation actor = CreateActorObservation();
        QuicBufferCopyObservation buffer = CreateBufferObservation();
        QuicAdaptiveBackpressureObservation adaptiveBackpressure =
            CreateAdaptiveBackpressureObservation();
        QuicAdaptiveRuntimeConnectionObservation connection =
            CreateConnectionObservation(epochSequence: 1);
        QuicReceiveCreditPolicySnapshot receiveCredit =
            CreateReceiveCreditSnapshot(epochSequence: 1);
        QuicAdaptiveRuntimePostServiceBoundary boundary =
            CreateBoundary(epochSequence: 1);
        Assert.True(accumulator.TryPublish(in actor));
        Assert.True(accumulator.TryPublish(in buffer));
        Assert.True(accumulator.TryPublish(in adaptiveBackpressure));
        Assert.True(accumulator.TryPublish(
            in connection,
            in receiveCredit,
            in boundary));
        QuicAdaptiveRuntimeUnifiedEpochEvidence evidence =
            Assert.Single(sink.Evidence);
        JsonSerializerOptions jsonOptions =
            new(JsonSerializerDefaults.Web);
        jsonOptions.Converters.Add(new JsonStringEnumConverter());

        string repoRoot =
            AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"unified-epoch-schema-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        try
        {
            string boundaryPath = Path.Combine(
                temporaryDirectory,
                "post-service-boundary.json");
            string unifiedPath = Path.Combine(
                temporaryDirectory,
                "unified-epoch.json");
            File.WriteAllText(
                boundaryPath,
                JsonSerializer.Serialize(
                    evidence.PostServiceBoundary,
                    jsonOptions));
            File.WriteAllText(
                unifiedPath,
                JsonSerializer.Serialize(evidence, jsonOptions));
            string boundarySchema = Path.Combine(
                repoRoot,
                "schemas",
                "adaptive-runtime-post-service-boundary-v1.schema.json");
            string unifiedSchema = Path.Combine(
                repoRoot,
                "schemas",
                "adaptive-runtime-unified-epoch-evidence-v11.schema.json");
            string command =
                $"$boundaryValid = Get-Content -LiteralPath "
                + $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(boundaryPath)} "
                + "-Raw | Test-Json -SchemaFile "
                + $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(boundarySchema)}; "
                + "$unifiedValid = Get-Content -LiteralPath "
                + $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(unifiedPath)} "
                + "-Raw | Test-Json -SchemaFile "
                + $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(unifiedSchema)}; "
                + "if (-not ($boundaryValid -and $unifiedValid)) { exit 1 }";
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
    [Requirement("REQ-QUIC-CRT-0184")]
    [Requirement("REQ-QUIC-CRT-0188")]
    [Requirement("REQ-QUIC-CRT-0189")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PermanentUnifiedRawExporterPreservesJoinedRowsAndManifest()
    {
        RecordingUnifiedSink sink = new();
        QuicAdaptiveRuntimeStage1PolicySnapshot configured =
            CreateLegacyStage1Policy();
        QuicBufferCopyConfiguredPolicySnapshot configuredBufferCopy =
            QuicBufferCopyPolicy.CreateConfiguredSnapshot(
                QuicBufferCopyObservationMode.ObserveOnly,
                forcedValue: null);
        QuicAdaptiveBackpressureConfiguredPolicySnapshot
            configuredAdaptiveBackpressure =
                QuicAdaptiveBackpressurePolicy.CreateConfiguredSnapshot(
                    QuicAdaptiveBackpressureObservationMode.ObserveOnly,
                    forcedValue: null);
        QuicPacketFlushCadenceConfiguredPolicySnapshot
            configuredPacketFlushCadence =
                QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
                    QuicPacketFlushCadenceObservationMode.ObserveOnly,
                    forcedValue: null);
        QuicReceiveDeliveryQuantumConfiguredPolicySnapshot
            configuredReceiveDeliveryQuantum =
                QuicReceiveDeliveryQuantumPolicy.CreateConfiguredSnapshot(
                    QuicReceiveDeliveryQuantumObservationMode.ObserveOnly,
                    forcedValue: null);
        QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator accumulator =
            new(
                in configured,
                in configuredBufferCopy,
                in configuredAdaptiveBackpressure,
                in configuredPacketFlushCadence,
                in configuredReceiveDeliveryQuantum,
                sink);
        QuicActorServiceObservation actor = CreateActorObservation();
        QuicBufferCopyObservation buffer = CreateBufferObservation();
        QuicAdaptiveBackpressureObservation adaptiveBackpressure =
            CreateAdaptiveBackpressureObservation();
        QuicPacketFlushCadenceObservation packetFlushCadence =
            CreatePacketFlushCadenceObservation();
        QuicReceiveDeliveryQuantumObservation receiveDeliveryQuantum =
            CreateReceiveDeliveryQuantumObservation();
        QuicConnectionShardPlacementDecision placement =
            CreateConnectionShardPlacementDecision();
        QuicAdaptiveRuntimeConnectionObservation connection =
            CreateConnectionObservation(epochSequence: 1);
        QuicReceiveCreditPolicySnapshot receiveCredit =
            CreateReceiveCreditSnapshot(epochSequence: 1);
        QuicAdaptiveRuntimePostServiceBoundary boundary =
            CreateBoundary(epochSequence: 1);
        Assert.True(accumulator.TryPublish(in actor));
        Assert.True(accumulator.TryPublish(in buffer));
        Assert.True(accumulator.TryPublish(in adaptiveBackpressure));
        Assert.True(accumulator.TryPublish(in packetFlushCadence));
        Assert.True(accumulator.TryPublish(in receiveDeliveryQuantum));
        Assert.True(accumulator.TryPublish(in placement));
        Assert.True(accumulator.TryPublish(
            in connection,
            in receiveCredit,
            in boundary));
        QuicAdaptiveRuntimeUnifiedEpochEvidence evidence =
            Assert.Single(sink.Evidence);

        string repoRoot =
            AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"unified-raw-exporter-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        try
        {
            JsonSerializerOptions jsonOptions =
                new(JsonSerializerDefaults.Web);
            jsonOptions.Converters.Add(new JsonStringEnumConverter());
            string rawJson = JsonSerializer.Serialize(
                new
                {
                    schemaVersion =
                        "adaptive-runtime-unified-epoch-raw-v11",
                    connectionKey = "connection-0001",
                    epoch = evidence,
                },
                jsonOptions);
            string actorRawJson = JsonSerializer.Serialize(
                new
                {
                    schemaVersion =
                        "adaptive-runtime-actor-service-raw-v4",
                    connectionKey = "connection-0001",
                    observation = actor,
                },
                jsonOptions);
            string adaptiveBackpressureRawJson = JsonSerializer.Serialize(
                new
                {
                    schemaVersion =
                        "quic-adaptive-backpressure-raw-v1",
                    connectionKey = "connection-0001",
                    observation = adaptiveBackpressure,
                },
                jsonOptions);
            string packetFlushCadenceRawJson = JsonSerializer.Serialize(
                new
                {
                    schemaVersion =
                        "quic-packet-flush-cadence-raw-v1",
                    connectionKey = "connection-0001",
                    observation = packetFlushCadence,
                },
                jsonOptions);
            string receiveDeliveryQuantumRawJson = JsonSerializer.Serialize(
                new
                {
                    schemaVersion =
                        "quic-receive-delivery-quantum-raw-v1",
                    connectionKey = "connection-0001",
                    observation = receiveDeliveryQuantum,
                },
                jsonOptions);
            string hostLogPath = Path.Combine(
                temporaryDirectory,
                "host.stdout.log");
            File.WriteAllLines(
                hostLogPath,
                [
                    "QUIC_ENDPOINT=127.0.0.1:4433",
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON="
                        + rawJson,
                    "QUIC_ACTOR_SERVICE_OBSERVATION_JSON="
                        + actorRawJson,
                    "QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON="
                        + adaptiveBackpressureRawJson,
                    "QUIC_PACKET_FLUSH_CADENCE_EVIDENCE_JSON="
                        + packetFlushCadenceRawJson,
                    "QUIC_RECEIVE_DELIVERY_QUANTUM_EVIDENCE_JSON="
                        + receiveDeliveryQuantumRawJson,
                ]);
            string outputDirectory = Path.Combine(
                temporaryDirectory,
                "export");

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
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
                9,
                summary.RootElement.GetProperty("axisRecordCount").GetInt32());
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("actorEpochRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("actorObservationRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("bufferObservationRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("adaptiveBackpressureEpochRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("adaptiveBackpressureObservationRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("packetFlushCadenceEpochRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("packetFlushCadenceObservationRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("receiveDeliveryQuantumEpochRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                summary.RootElement
                    .GetProperty("receiveDeliveryQuantumObservationRowCount")
                    .GetInt32());
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "adaptive-runtime-unified-raw-epochs.jsonl")));
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "adaptive-runtime-actor-service-observations.jsonl")));
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "adaptive-runtime-backpressure-observations.jsonl")));
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "adaptive-runtime-packet-flush-cadence-observations.jsonl")));
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "adaptive-runtime-receive-delivery-quantum-observations.jsonl")));
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "raw-validation-summary.json")));
            Assert.True(File.Exists(Path.Combine(
                outputDirectory,
                "raw-export-manifest.json")));

            string failedHostLogPath = Path.Combine(
                temporaryDirectory,
                "failed-host.log");
            File.WriteAllLines(
                failedHostLogPath,
                [
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON="
                        + rawJson,
                    "QUIC_ACTOR_SERVICE_OBSERVATION_JSON="
                        + actorRawJson,
                    "QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON="
                        + adaptiveBackpressureRawJson,
                    "QUIC_PACKET_FLUSH_CADENCE_EVIDENCE_JSON="
                        + packetFlushCadenceRawJson,
                    "QUIC_RECEIVE_DELIVERY_QUANTUM_EVIDENCE_JSON="
                        + receiveDeliveryQuantumRawJson,
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_FAILURE_JSON="
                        + JsonSerializer.Serialize(
                            new
                            {
                                schemaVersion =
                                    "adaptive-runtime-unified-epoch-export-failure-v1",
                                connectionKey = "connection-0001",
                                connectionEpochSequence = 2,
                                rawEpochPublished = true,
                                stage1EpochPublished = true,
                                unifiedEpochPublished = false,
                            },
                            jsonOptions),
                ]);
            string failedOutputDirectory = Path.Combine(
                temporaryDirectory,
                "failed-export");
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult failed =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
                    "-HostLogPath",
                    failedHostLogPath,
                    "-OutputDirectory",
                    failedOutputDirectory);
            Assert.NotEqual(0, failed.ExitCode);
            Assert.True(File.Exists(Path.Combine(
                failedOutputDirectory,
                "raw-export-failures.jsonl")));
            using JsonDocument failedManifest = JsonDocument.Parse(
                File.ReadAllText(Path.Combine(
                    failedOutputDirectory,
                    "raw-export-manifest.json")));
            Assert.Equal(
                "invalid_contract",
                failedManifest.RootElement
                    .GetProperty("classification")
                    .GetString());
            Assert.Equal(
                1,
                failedManifest.RootElement
                    .GetProperty("exportFailureCount")
                    .GetInt32());

            string actorFailedHostLogPath = Path.Combine(
                temporaryDirectory,
                "actor-failed-host.log");
            File.WriteAllLines(
                actorFailedHostLogPath,
                [
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON="
                        + rawJson,
                    "QUIC_ACTOR_SERVICE_OBSERVATION_JSON="
                        + actorRawJson,
                    "QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON="
                        + adaptiveBackpressureRawJson,
                    "QUIC_PACKET_FLUSH_CADENCE_EVIDENCE_JSON="
                        + packetFlushCadenceRawJson,
                    "QUIC_RECEIVE_DELIVERY_QUANTUM_EVIDENCE_JSON="
                        + receiveDeliveryQuantumRawJson,
                    "QUIC_ACTOR_SERVICE_OBSERVATION_FAILURE_JSON="
                        + JsonSerializer.Serialize(
                            new
                            {
                                schemaVersion =
                                    "adaptive-runtime-actor-service-export-failure-v1",
                                connectionKey = "connection-0001",
                                serviceSequence = 2,
                            },
                            jsonOptions),
                ]);
            string actorFailedOutputDirectory = Path.Combine(
                temporaryDirectory,
                "actor-failed-export");
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult actorFailed =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
                    "-HostLogPath",
                    actorFailedHostLogPath,
                    "-OutputDirectory",
                    actorFailedOutputDirectory);
            Assert.NotEqual(0, actorFailed.ExitCode);
            using JsonDocument actorFailedManifest = JsonDocument.Parse(
                File.ReadAllText(Path.Combine(
                    actorFailedOutputDirectory,
                    "raw-export-manifest.json")));
            Assert.Equal(
                "invalid_contract",
                actorFailedManifest.RootElement
                    .GetProperty("classification")
                    .GetString());
            Assert.Equal(
                1,
                actorFailedManifest.RootElement
                    .GetProperty("actorExportFailureCount")
                    .GetInt32());

            string missingActorHostLogPath = Path.Combine(
                temporaryDirectory,
                "missing-actor-host.log");
            File.WriteAllLines(
                missingActorHostLogPath,
                [
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON="
                        + rawJson,
                    "QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON="
                        + adaptiveBackpressureRawJson,
                ]);
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult missingActor =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
                    "-HostLogPath",
                    missingActorHostLogPath,
                    "-OutputDirectory",
                    Path.Combine(temporaryDirectory, "missing-actor-export"));
            Assert.NotEqual(0, missingActor.ExitCode);
            Assert.Contains(
                "actorMissing=1",
                missingActor.Output,
                StringComparison.Ordinal);

            string missingBackpressureHostLogPath = Path.Combine(
                temporaryDirectory,
                "missing-backpressure-host.log");
            File.WriteAllLines(
                missingBackpressureHostLogPath,
                [
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON="
                        + rawJson,
                    "QUIC_ACTOR_SERVICE_OBSERVATION_JSON="
                        + actorRawJson,
                ]);
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult
                missingBackpressure =
                    AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                        "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
                        "-HostLogPath",
                        missingBackpressureHostLogPath,
                        "-OutputDirectory",
                        Path.Combine(
                            temporaryDirectory,
                            "missing-backpressure-export"));
            Assert.NotEqual(0, missingBackpressure.ExitCode);
            Assert.Contains(
                "backpressureMissing=1",
                missingBackpressure.Output,
                StringComparison.Ordinal);

            string missingReceiveDeliveryHostLogPath = Path.Combine(
                temporaryDirectory,
                "missing-receive-delivery-host.log");
            File.WriteAllLines(
                missingReceiveDeliveryHostLogPath,
                [
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON="
                        + rawJson,
                    "QUIC_ACTOR_SERVICE_OBSERVATION_JSON="
                        + actorRawJson,
                    "QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON="
                        + adaptiveBackpressureRawJson,
                    "QUIC_PACKET_FLUSH_CADENCE_EVIDENCE_JSON="
                        + packetFlushCadenceRawJson,
                ]);
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult
                missingReceiveDelivery =
                    AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                        "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
                        "-HostLogPath",
                        missingReceiveDeliveryHostLogPath,
                        "-OutputDirectory",
                        Path.Combine(
                            temporaryDirectory,
                            "missing-receive-delivery-export"));
            Assert.NotEqual(0, missingReceiveDelivery.ExitCode);
            Assert.Contains(
                "receiveDeliveryMissing=1",
                missingReceiveDelivery.Output,
                StringComparison.Ordinal);

            QuicAdaptiveRuntimeUnifiedEpochEvidence mismatchedEvidence =
                evidence with
                {
                    ActorService = evidence.ActorService with
                    {
                        MaximumServiceContenderCount = 2,
                    },
                };
            string mismatchedHostLogPath = Path.Combine(
                temporaryDirectory,
                "mismatched-contender-host.log");
            File.WriteAllLines(
                mismatchedHostLogPath,
                [
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON="
                        + JsonSerializer.Serialize(
                            new
                            {
                                schemaVersion =
                                    "adaptive-runtime-unified-epoch-raw-v11",
                                connectionKey = "connection-0001",
                                epoch = mismatchedEvidence,
                            },
                            jsonOptions),
                    "QUIC_ACTOR_SERVICE_OBSERVATION_JSON="
                        + actorRawJson,
                    "QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON="
                        + adaptiveBackpressureRawJson,
                    "QUIC_PACKET_FLUSH_CADENCE_EVIDENCE_JSON="
                        + packetFlushCadenceRawJson,
                    "QUIC_RECEIVE_DELIVERY_QUANTUM_EVIDENCE_JSON="
                        + receiveDeliveryQuantumRawJson,
                ]);
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult
                mismatchedContender =
                    AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                        "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
                        "-HostLogPath",
                        mismatchedHostLogPath,
                        "-OutputDirectory",
                        Path.Combine(
                            temporaryDirectory,
                            "mismatched-contender-export"));
            Assert.NotEqual(0, mismatchedContender.ExitCode);
            Assert.Contains(
                "joinFailures=1",
                mismatchedContender.Output,
                StringComparison.Ordinal);

            QuicAdaptiveRuntimeUnifiedEpochEvidence
                mismatchedAcceptedWorkEvidence =
                    evidence with
                    {
                        ActorService = evidence.ActorService with
                        {
                            TotalAcceptedConnectionWorkItemsAfterCurrent = 1,
                            MaximumAcceptedConnectionWorkItemsAfterCurrent = 1,
                            TurnsWithAcceptedConnectionWorkRemaining = 1,
                        },
                    };
            string mismatchedAcceptedWorkHostLogPath = Path.Combine(
                temporaryDirectory,
                "mismatched-accepted-work-host.log");
            File.WriteAllLines(
                mismatchedAcceptedWorkHostLogPath,
                [
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON="
                        + JsonSerializer.Serialize(
                            new
                            {
                                schemaVersion =
                                    "adaptive-runtime-unified-epoch-raw-v11",
                                connectionKey = "connection-0001",
                                epoch = mismatchedAcceptedWorkEvidence,
                            },
                            jsonOptions),
                    "QUIC_ACTOR_SERVICE_OBSERVATION_JSON="
                        + actorRawJson,
                    "QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON="
                        + adaptiveBackpressureRawJson,
                    "QUIC_PACKET_FLUSH_CADENCE_EVIDENCE_JSON="
                        + packetFlushCadenceRawJson,
                    "QUIC_RECEIVE_DELIVERY_QUANTUM_EVIDENCE_JSON="
                        + receiveDeliveryQuantumRawJson,
                ]);
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult
                mismatchedAcceptedWork =
                    AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                        "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
                        "-HostLogPath",
                        mismatchedAcceptedWorkHostLogPath,
                        "-OutputDirectory",
                        Path.Combine(
                            temporaryDirectory,
                            "mismatched-accepted-work-export"));
            Assert.NotEqual(0, mismatchedAcceptedWork.ExitCode);
            Assert.Contains(
                "joinFailures=1",
                mismatchedAcceptedWork.Output,
                StringComparison.Ordinal);

            QuicAdaptiveRuntimeUnifiedEpochEvidence
                mismatchedContinuationEvidence =
                    evidence with
                    {
                        ActorService = evidence.ActorService with
                        {
                            ApplicationSendContinuationReadyTurnCount = 1,
                            MaximumApplicationSendContinuationRemainingCount =
                                1,
                        },
                    };
            string mismatchedContinuationHostLogPath = Path.Combine(
                temporaryDirectory,
                "mismatched-continuation-host.log");
            File.WriteAllLines(
                mismatchedContinuationHostLogPath,
                [
                    "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON="
                        + JsonSerializer.Serialize(
                            new
                            {
                                schemaVersion =
                                    "adaptive-runtime-unified-epoch-raw-v11",
                                connectionKey = "connection-0001",
                                epoch = mismatchedContinuationEvidence,
                            },
                            jsonOptions),
                    "QUIC_ACTOR_SERVICE_OBSERVATION_JSON="
                        + actorRawJson,
                    "QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON="
                        + adaptiveBackpressureRawJson,
                    "QUIC_PACKET_FLUSH_CADENCE_EVIDENCE_JSON="
                        + packetFlushCadenceRawJson,
                    "QUIC_RECEIVE_DELIVERY_QUANTUM_EVIDENCE_JSON="
                        + receiveDeliveryQuantumRawJson,
                ]);
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult
                mismatchedContinuation =
                    AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                        "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
                        "-HostLogPath",
                        mismatchedContinuationHostLogPath,
                        "-OutputDirectory",
                        Path.Combine(
                            temporaryDirectory,
                            "mismatched-continuation-export"));
            Assert.NotEqual(0, mismatchedContinuation.ExitCode);
            Assert.Contains(
                "joinFailures=1",
                mismatchedContinuation.Output,
                StringComparison.Ordinal);

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult second =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1",
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

    private static QuicAdaptiveRuntimeStage1PolicySnapshot
        CreateLegacyStage1Policy()
        => QuicAdaptiveRuntimeStage1ConfiguredPolicy.Create(
            sendTurnForced: null,
            QuicApplicationSendTurnObservationMode.ObserveOnly,
            sendBatchForced: null,
            QuicApplicationSendBatchObservationMode.ObserveOnly,
            burstForced: null,
            QuicQueuedSendBurstObservationMode.ObserveOnly,
            oversizedForced: null,
            QuicOversizedWriteAdmissionObservationMode.ObserveOnly);

    private static QuicAdaptiveRuntimeStage1PolicySnapshot
        CreateDisabledStage1Policy()
        => QuicAdaptiveRuntimeStage1ConfiguredPolicy.Create(
            sendTurnForced: null,
            QuicApplicationSendTurnObservationMode.Disabled,
            sendBatchForced: null,
            QuicApplicationSendBatchObservationMode.Disabled,
            burstForced: null,
            QuicQueuedSendBurstObservationMode.Disabled,
            oversizedForced: null,
            QuicOversizedWriteAdmissionObservationMode.Disabled);

    private static QuicAdaptiveRuntimeConnectionObservation
        CreateConnectionObservation(ulong epochSequence)
        => new(
            epochSequence,
            EpochStartTicks: 10,
            EpochEndTicks: 20,
            ActiveDurationMicros: 1,
            QuicAdaptiveRuntimeConnectionObservation
                .CurrentObservationContractVersion,
            QuicAdaptiveRuntimeConnectionObservation.CurrentPolicyRuleVersion,
            AdvisorAgeMicros: null,
            MissingSignalMask: QuicAdaptiveRuntimeSignalMask.None,
            StaleSignalMask: QuicAdaptiveRuntimeSignalMask.None,
            LifecycleFlags: QuicAdaptiveRuntimeLifecycle.Active,
            HasIssuedApplicationData: false,
            OpenStreams: 0,
            LiveObserverStreams: 0,
            QueuedApplicationWrites: 0,
            QueueDelayEwmaMicros: 0);

    private static QuicReceiveCreditPolicySnapshot
        CreateReceiveCreditSnapshot(ulong epochSequence)
        => new(
            SnapshotVersion: epochSequence,
            QuicAdaptiveRuntimeConnectionObservation.CurrentPolicyRuleVersion,
            QuicAdaptiveRuntimePolicyState.Conservative,
            QuicAdaptiveRuntimePolicyState.Conservative,
            Transitioned: false,
            StateEpochCount: 1,
            StateDurationMicros: 1,
            CandidateEvidenceCount: 0,
            ReliefEvidenceCount: 0,
            EpochSequence: epochSequence,
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            QuicReceiveCreditPolicyMode.Immediate,
            QuicAdaptiveRuntimePolicyReason.LegacyImmediate,
            HasIssuedApplicationData: false);

    private static QuicAdaptiveRuntimePostServiceBoundary
        CreateBoundary(ulong epochSequence)
        => new(
            epochSequence,
            EpochEndTicks: 20,
            QuicAdaptiveRuntimePostServiceBoundarySource.HostedShard,
            QuicActorServiceDisposition.Completed,
            ActorServiceSequence: 1,
            ActorObservationPublished: true,
            ResourceReleaseCompleted: true,
            QuicAdaptiveRuntimePostServiceBoundaryValidity.None);

    private static QuicActorServiceObservation CreateActorObservation()
        => new(
            ServiceSequence: 1,
            ShardIndex: 1,
            WakeSequence: 1,
            WakePosition: 1,
            QuicActorWakeCompletion.Synchronous,
            QuicActorWakeSource.Inbox,
            QuicActorWorkKind.FlowControlCreditUpdate,
            QuicActorServiceDisposition.Completed,
            QueueDelayMicros: 1,
            ServiceTimeMicros: 1,
            PendingWorkItemsAfterDequeue: 0,
            EffectCount: 0,
            ApplicationSendFollowOnCount: 0,
            FlowControlFollowOnCount: 0,
            StreamCapacityFollowOnCount: 0,
            QuicConnectionPhase.Active,
            DisposalStarted: false,
            QuicActorServiceValidity.None,
            ServiceContenderCountAtStart: 1,
            AcceptedConnectionWorkItemsAfterCurrent: 0,
            ContinuationAssessment: new(
                QuicActorContinuationAssessmentState.Drained,
                ApplicationSendRemainingCount: 0,
                QuicActorContinuationAssessmentState.Drained,
                FlowControlRemainingCount: 0,
                QuicActorContinuationAssessmentState.Drained,
                StreamCapacityRemainingCount: 0));

    private static QuicBufferCopyObservation CreateBufferObservation()
        => new(
            OperationSequence: 1,
            QuicBufferCopyObservationMode.ObserveOnly,
            QuicBufferCopyPath.ApplicationWriteRequest,
            QuicBufferCopyOperation.Copy,
            QuicBufferCopyDecisionBoundary.StreamWriteRetry,
            JoinOperationSequence: 1,
            LegalLogicalBytes: 8,
            LogicalBytes: 8,
            CopiedBytes: 8,
            LegalSourceSegmentCount: 1,
            SourceSegmentCount: 1,
            DestinationSegmentCount: 1,
            RequestedCapacityBytes: 8,
            RetainedCapacityBytes: 8,
            ForcedValue: null,
            ShadowRecommendation: null,
            QuicBufferCopyPolicyValue.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent,
            QuicBufferCopySelectionSource.LegacyCurrent,
            QuicBufferCopyReasonCode.LegacyCopy,
            QuicBufferCopySafetyOverride.None,
            QuicBufferCopyLatchLifetime.BufferLifetime,
            FallbackApplied: false,
            QuicConnectionPhase.Active,
            DisposalStarted: false,
            QuicBufferCopyValidity.None);

    private static QuicAdaptiveBackpressureObservation
        CreateAdaptiveBackpressureObservation()
        => new(
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

    private static QuicPacketFlushCadenceObservation
        CreatePacketFlushCadenceObservation()
        => new(
            OperationSequence: 1,
            RequestId: 1,
            QuicPacketFlushCadenceObservationMode.ObserveOnly,
            ForcedValue: null,
            ShadowRecommendation: null,
            QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            QuicPacketFlushCadencePolicyValue.LegacyCurrent,
            QuicPacketFlushCadenceSelectionSource.LegacyCurrent,
            QuicPacketFlushCadenceReasonCode.LegacyDelay,
            QuicPacketFlushCadenceSafetyOverride.None,
            QuicPacketFlushCadenceDecisionBoundary
                .AuthorizedApplicationPacketConstruction,
            QuicPacketFlushCadenceLatchLifetime
                .LogicalWritePacketOpportunity,
            FallbackApplied: false,
            LegacyDelayEligible: true,
            DelayApplied: true,
            PromptFlushApplied: false,
            StreamPayloadLength: 16,
            QueuedWriteCount: 0,
            FinishWrites: false,
            AddressValidated: true,
            RetransmissionPending: false,
            QuicConnectionPhase.Active,
            DisposalStarted: false,
            QuicPacketFlushCadenceValidity.None);

    private static QuicReceiveDeliveryQuantumObservation
        CreateReceiveDeliveryQuantumObservation()
    {
        QuicReceiveDeliveryQuantumPolicyDecision decision =
            QuicReceiveDeliveryQuantumPolicy.Evaluate(
                QuicReceiveDeliveryQuantumObservationMode.ObserveOnly,
                forcedValue: null,
                requestedBufferLength: 64,
                lifecycleGuard: false);
        return new(
            OperationSequence: 1,
            StreamId: 0,
            decision,
            DeliveredBytes: 16,
            SourceSegmentsRead: 1,
            Completed: false,
            BatchedReceiveCredit: false);
    }

    private static QuicConnectionShardPlacementDecision
        CreateConnectionShardPlacementDecision()
        => QuicConnectionShardPlacementPolicy.Evaluate(
            QuicConnectionShardPlacementObservationMode.ObserveOnly,
            forcedValue: null,
            connectionHandleValue: 1,
            shardCount: 4,
            legacyShardActiveConnections: 0,
            alternateShardActiveConnections: 0,
            lifecycleGuard: false);

    private sealed class RecordingPostServiceSink :
        IQuicAdaptiveRuntimeShadowEpochSink,
        IQuicActorServiceEvidenceSink
    {
        private int actorObservationCount;

        internal TaskCompletionSource EpochPublished { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal int ActorObservationCountAtEpoch { get; private set; }

        internal QuicAdaptiveRuntimeConnectionObservation Observation
        {
            get;
            private set;
        }

        internal QuicAdaptiveRuntimePostServiceBoundary Boundary
        {
            get;
            private set;
        }

        public bool TryPublish(in QuicActorServiceObservation observation)
        {
            actorObservationCount++;
            return true;
        }

        public bool TryPublish(
            in QuicAdaptiveRuntimeConnectionObservation observation,
            in QuicReceiveCreditPolicySnapshot snapshot,
            in QuicAdaptiveRuntimePostServiceBoundary boundary)
        {
            Observation = observation;
            Boundary = boundary;
            ActorObservationCountAtEpoch = actorObservationCount;
            EpochPublished.TrySetResult();
            return true;
        }
    }

    private sealed class RecordingUnifiedSink :
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink
    {
        internal TaskCompletionSource EpochPublished { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal List<QuicAdaptiveRuntimeUnifiedEpochEvidence> Evidence
        {
            get;
        } = [];

        public bool TryPublish(
            in QuicAdaptiveRuntimeUnifiedEpochEvidence evidence)
        {
            Evidence.Add(evidence);
            EpochPublished.TrySetResult();
            return true;
        }
    }
}

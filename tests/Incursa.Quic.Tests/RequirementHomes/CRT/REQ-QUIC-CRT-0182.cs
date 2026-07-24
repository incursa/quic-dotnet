// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0182")]
public sealed class REQ_QUIC_CRT_0182
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ObserveOnlyCopyOperationsRemainLegacyAndAccumulate()
    {
        QuicBufferCopyEpochAccumulator accumulator = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = accumulator,
        });

        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.FormattedStreamPayload,
            QuicBufferCopyOperation.Format,
            QuicBufferCopyDecisionBoundary.PacketPlan,
            joinOperationSequence: null,
            logicalBytes: 100,
            copiedBytes: 100,
            sourceSegmentCount: 1,
            requestedCapacityBytes: 120,
            retainedCapacityBytes: 128);
        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.CombinedApplicationSend,
            QuicBufferCopyOperation.Combine,
            QuicBufferCopyDecisionBoundary.PacketPlan,
            joinOperationSequence: null,
            logicalBytes: 200,
            copiedBytes: 200,
            sourceSegmentCount: 2,
            requestedCapacityBytes: 200,
            retainedCapacityBytes: 256);

        QuicBufferCopyEpochSummary summary =
            accumulator.CaptureAndReset();
        Assert.True(summary.HasObservation);
        Assert.Equal(1UL, summary.FirstOperationSequence);
        Assert.Equal(2UL, summary.LastOperationSequence);
        Assert.Equal(2UL, summary.OperationCount);
        Assert.Equal(1UL, summary.FormattedStreamPayloadCount);
        Assert.Equal(1UL, summary.CombinedApplicationSendCount);
        Assert.Equal(1UL, summary.FormatCount);
        Assert.Equal(1UL, summary.CombineCount);
        Assert.Equal(300UL, summary.TotalLogicalBytes);
        Assert.Equal(300UL, summary.TotalCopiedBytes);
        Assert.Equal(384UL, summary.TotalRetainedCapacityBytes);
        Assert.True(
            (summary.Validity
                & QuicBufferCopyValidity.MissingTerminalReleaseCorrelation)
            != 0);

        Assert.False(accumulator.CaptureAndReset().HasObservation);
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
                    BufferCopyObservationMode =
                        QuicBufferCopyObservationMode.ObserveOnly,
                }));

        using QuicConnectionRuntime disabledWithSink = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => disabledWithSink.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyEvidenceSink =
                        new QuicBufferCopyEpochAccumulator(),
                }));

        using QuicConnectionRuntime invalidMode = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<ArgumentOutOfRangeException>(
            () => invalidMode.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyObservationMode =
                        (QuicBufferCopyObservationMode)byte.MaxValue,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionCopyPreservesBufferObservationModeAndSink()
    {
        QuicBufferCopyEpochAccumulator sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(
            selectedOptions,
            returnedOptions);

        Assert.Equal(
            QuicBufferCopyObservationMode.ObserveOnly,
            selectedOptions.BufferCopyObservationMode);
        Assert.Same(sink, selectedOptions.BufferCopyEvidenceSink);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ThrowingEvidenceSinkCannotInterruptCopyOwnershipPath()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = new ThrowingSink(),
        });

        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.OversizedRawQueue,
            QuicBufferCopyOperation.Copy,
            QuicBufferCopyDecisionBoundary.LogicalWriteAdmission,
            joinOperationSequence: 1,
            logicalBytes: 64,
            copiedBytes: 64,
            sourceSegmentCount: 1,
            requestedCapacityBytes: 64,
            retainedCapacityBytes: 64);
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
            $"buffer-copy-validator-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            RecordingSink sink = new();
            using QuicConnectionRuntime runtime = new(
                QuicConnectionStreamStateTestHelpers.CreateState());
            runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyObservationMode =
                        QuicBufferCopyObservationMode.ObserveOnly,
                    BufferCopyEvidenceSink = sink,
                });
            runtime.TryPublishBufferCopyObservation(
                QuicBufferCopyPath.SentPacketPlaintextRetention,
                QuicBufferCopyOperation.Retain,
                QuicBufferCopyDecisionBoundary.SentPacketRetention,
                joinOperationSequence: 7,
                logicalBytes: 80,
                copiedBytes: 80,
                sourceSegmentCount: 1,
                requestedCapacityBytes: 80,
                retainedCapacityBytes: 128);
            QuicBufferCopyObservation observation =
                Assert.Single(sink.Observations);
            QuicBufferCopyEpochAccumulator accumulator = new();
            Assert.True(accumulator.TryPublish(in observation));
            QuicBufferCopyEpochSummary summary =
                accumulator.CaptureAndReset();

            JsonSerializerOptions options =
                new(JsonSerializerDefaults.Web);
            options.Converters.Add(new JsonStringEnumConverter());
            string observationPath = Path.Combine(
                temporaryDirectory,
                "buffer-copy-observations.jsonl");
            string epochPath = Path.Combine(
                temporaryDirectory,
                "buffer-copy-epoch.json");
            File.WriteAllText(
                observationPath,
                JsonSerializer.Serialize(observation, options));
            File.WriteAllText(
                epochPath,
                JsonSerializer.Serialize(summary, options));

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimeBufferCopyEvidence.ps1",
                    "-ObservationPath",
                    observationPath,
                    "-EpochSummaryPath",
                    epochPath);

            Assert.True(result.ExitCode == 0, result.Output);
            using JsonDocument validation =
                JsonDocument.Parse(result.Output);
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
                    .GetProperty("operationCount")
                    .GetInt32());
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private sealed class RecordingSink : IQuicBufferCopyEvidenceSink
    {
        internal List<QuicBufferCopyObservation> Observations { get; } = [];

        public bool TryPublish(
            in QuicBufferCopyObservation observation)
        {
            Observations.Add(observation);
            return true;
        }
    }

    private sealed class ThrowingSink : IQuicBufferCopyEvidenceSink
    {
        public bool TryPublish(
            in QuicBufferCopyObservation observation)
            => throw new InvalidOperationException("diagnostic sink failure");
    }
}

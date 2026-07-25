// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0193")]
public sealed class REQ_QUIC_CRT_0193
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedSingleSegmentReturnsAOneSegmentPlan()
    {
        QuicReceiveDeliveryQuantumPolicyDecision decision =
            QuicReceiveDeliveryQuantumPolicy.Evaluate(
                QuicReceiveDeliveryQuantumObservationMode.Disabled,
                QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
                requestedBufferLength: 4096,
                lifecycleGuard: false);

        Assert.Equal(1, decision.MaximumSourceSegments);
        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
            decision.SelectedValue);
        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
            decision.AppliedValue);
        Assert.Equal(
            QuicReceiveDeliveryQuantumSelectionSource.Forced,
            decision.SelectionSource);
        Assert.Equal(
            QuicReceiveDeliveryQuantumReasonCode.SingleSegmentApplied,
            decision.ReasonCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackRetainsAllAvailableSegments()
    {
        QuicReceiveDeliveryQuantumPolicyDecision decision =
            QuicReceiveDeliveryQuantumPolicy.Evaluate(
                QuicReceiveDeliveryQuantumObservationMode.Disabled,
                QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
                requestedBufferLength: 4096,
                lifecycleGuard: false);

        Assert.Equal(int.MaxValue, decision.MaximumSourceSegments);
        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicReceiveDeliveryQuantumReasonCode.LegacyAllAvailable,
            decision.ReasonCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowRecommendsSingleSegmentWhileApplyingLegacy()
    {
        QuicReceiveDeliveryQuantumPolicyDecision decision =
            QuicReceiveDeliveryQuantumPolicy.Evaluate(
                QuicReceiveDeliveryQuantumObservationMode.Shadow,
                forcedValue: null,
                requestedBufferLength: 4096,
                lifecycleGuard: false);

        Assert.True(decision.HasShadowRecommendation);
        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
            decision.ShadowRecommendation);
        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
            decision.SelectedValue);
        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(int.MaxValue, decision.MaximumSourceSegments);
    }

    [Theory]
    [InlineData(
        (byte)QuicReceiveDeliveryQuantumValidity.MissingRequiredInput,
        (byte)QuicReceiveDeliveryQuantumReasonCode.MissingInput)]
    [InlineData(
        (byte)QuicReceiveDeliveryQuantumValidity.StaleRequiredInput,
        (byte)QuicReceiveDeliveryQuantumReasonCode.StaleInput)]
    [InlineData(
        (byte)QuicReceiveDeliveryQuantumValidity.ArithmeticSaturated,
        (byte)QuicReceiveDeliveryQuantumReasonCode.ArithmeticSaturated)]
    [InlineData(
        (byte)QuicReceiveDeliveryQuantumValidity.Contradictory,
        (byte)QuicReceiveDeliveryQuantumReasonCode.Contradictory)]
    [InlineData(
        (byte)QuicReceiveDeliveryQuantumValidity.OutOfDomain,
        (byte)QuicReceiveDeliveryQuantumReasonCode.OutOfDomain)]
    [InlineData(
        (byte)QuicReceiveDeliveryQuantumValidity.InvalidInput,
        (byte)QuicReceiveDeliveryQuantumReasonCode.InvalidInput)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidInputsFallBackEvenWhenSingleSegmentIsForced(
        byte validityValue,
        byte expectedReasonValue)
    {
        QuicReceiveDeliveryQuantumPolicyDecision decision =
            QuicReceiveDeliveryQuantumPolicy.Evaluate(
                QuicReceiveDeliveryQuantumObservationMode.Shadow,
                QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
                requestedBufferLength: 4096,
                lifecycleGuard: false,
                (QuicReceiveDeliveryQuantumValidity)validityValue);

        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
            decision.SelectedValue);
        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(int.MaxValue, decision.MaximumSourceSegments);
        Assert.Equal(
            QuicReceiveDeliveryQuantumSelectionSource.SafetyOverride,
            decision.SelectionSource);
        Assert.Equal(
            (QuicReceiveDeliveryQuantumReasonCode)expectedReasonValue,
            decision.ReasonCode);
        Assert.True(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LifecycleGuardOverridesForcedSingleSegment()
    {
        QuicReceiveDeliveryQuantumPolicyDecision decision =
            QuicReceiveDeliveryQuantumPolicy.Evaluate(
                QuicReceiveDeliveryQuantumObservationMode.Disabled,
                QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
                requestedBufferLength: 4096,
                lifecycleGuard: true);

        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(int.MaxValue, decision.MaximumSourceSegments);
        Assert.Equal(
            QuicReceiveDeliveryQuantumReasonCode.LifecycleGuard,
            decision.ReasonCode);
        Assert.True(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void StreamStateCanDeliverExactlyOneContiguousSourceSegment()
    {
        QuicConnectionStreamState state =
            QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 16,
                peerBidirectionalReceiveLimit: 8);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x33, 0x44], offset: 2),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x11, 0x22], offset: 0),
            out errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: false,
            maximumSourceSegments: 1,
            out int bytesWritten,
            out int sourceSegmentsRead,
            out bool completed,
            out _,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.Equal(1, sourceSegmentsRead);
        Assert.False(completed);
        Assert.True(new byte[] { 0x11, 0x22 }.AsSpan()
            .SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void StreamStateLegacyPlanStillDeliversAllAvailableSegments()
    {
        QuicConnectionStreamState state =
            QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 16,
                peerBidirectionalReceiveLimit: 8);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x33, 0x44], offset: 2),
            out QuicTransportErrorCode errorCode));
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x11, 0x22], offset: 0),
            out errorCode));

        Span<byte> destination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: false,
            maximumSourceSegments: int.MaxValue,
            out int bytesWritten,
            out int sourceSegmentsRead,
            out _,
            out _,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.Equal(2, sourceSegmentsRead);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedRuntimePlanAppliesOneSegmentAndPublishesOutcome()
    {
        QuicConnectionStreamState state =
            QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 16,
                peerBidirectionalReceiveLimit: 8);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x33, 0x44], offset: 2),
            out QuicTransportErrorCode errorCode));
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x11, 0x22], offset: 0),
            out errorCode));
        RecordingReceiveDeliverySink sink = new();
        using QuicConnectionRuntime runtime = new(state);
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ForcedReceiveCreditPolicyMode =
                    QuicReceiveCreditPolicyMode.LegacyCurrent,
                ForcedReceiveDeliveryQuantumPolicyValue =
                    QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
                ReceiveDeliveryQuantumObservationMode =
                    QuicReceiveDeliveryQuantumObservationMode.ObserveOnly,
                ReceiveDeliveryQuantumEvidenceSink = sink,
            });
        QuicReceiveDeliveryQuantumPolicyDecision decision =
            runtime.ResolveReceiveDeliveryQuantumPolicyDecision(4);
        Span<byte> destination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: false,
            decision.MaximumSourceSegments,
            out int bytesRead,
            out int sourceSegmentsRead,
            out bool completed,
            out _,
            out _,
            out errorCode));
        runtime.TryPublishReceiveDeliveryQuantumObservation(
            1,
            in decision,
            bytesRead,
            sourceSegmentsRead,
            completed,
            batchedReceiveCredit: false);

        Assert.Equal(2, bytesRead);
        QuicReceiveDeliveryQuantumObservation observation =
            Assert.Single(sink.Observations);
        Assert.Equal(2U, observation.DeliveredBytes);
        Assert.Equal(1U, observation.SourceSegmentsRead);
        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
            observation.Decision.AppliedValue);
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
                    ReceiveDeliveryQuantumObservationMode =
                        QuicReceiveDeliveryQuantumObservationMode.ObserveOnly,
                }));

        using QuicConnectionRuntime disabledWithSink =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => disabledWithSink.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ReceiveDeliveryQuantumEvidenceSink =
                        new RecordingReceiveDeliverySink(),
                }));

        using QuicConnectionRuntime adjacent =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => adjacent.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ForcedReceiveCreditPolicyMode =
                        QuicReceiveCreditPolicyMode.LegacyCurrent,
                    ForcedPacketFlushCadencePolicyValue =
                        QuicPacketFlushCadencePolicyValue.Prompt,
                    ForcedReceiveDeliveryQuantumPolicyValue =
                        QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
                }));

        using QuicConnectionRuntime implicitReceiveCredit =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => implicitReceiveCredit.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ForcedReceiveDeliveryQuantumPolicyValue =
                        QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ThrowingSinkCannotChangeDelivery()
    {
        QuicConnectionStreamState state =
            QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 16,
                peerBidirectionalReceiveLimit: 8);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x11, 0x22], offset: 0),
            out _));
        using QuicConnectionRuntime runtime = new(state);
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ForcedReceiveCreditPolicyMode =
                    QuicReceiveCreditPolicyMode.LegacyCurrent,
                ReceiveDeliveryQuantumObservationMode =
                    QuicReceiveDeliveryQuantumObservationMode.ObserveOnly,
                ReceiveDeliveryQuantumEvidenceSink =
                    new ThrowingReceiveDeliverySink(),
            });
        QuicReceiveDeliveryQuantumPolicyDecision decision =
            runtime.ResolveReceiveDeliveryQuantumPolicyDecision(2);
        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: false,
            decision.MaximumSourceSegments,
            out int bytesRead,
            out int sourceSegmentsRead,
            out bool completed,
            out _,
            out _,
            out _));
        runtime.TryPublishReceiveDeliveryQuantumObservation(
            1,
            in decision,
            bytesRead,
            sourceSegmentsRead,
            completed,
            batchedReceiveCredit: false);
        Assert.Equal(2, bytesRead);
        Assert.True(new byte[] { 0x11, 0x22 }.AsSpan()
            .SequenceEqual(destination));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EpochAndRawSchemasPreserveExactOperationJoinAndOutcomes()
    {
        QuicReceiveDeliveryQuantumConfiguredPolicySnapshot configured =
            QuicReceiveDeliveryQuantumPolicy.CreateConfiguredSnapshot(
                QuicReceiveDeliveryQuantumObservationMode.ObserveOnly,
                forcedValue: null);
        QuicReceiveDeliveryQuantumEpochAccumulator accumulator =
            new(in configured);
        QuicReceiveDeliveryQuantumPolicyDecision decision =
            QuicReceiveDeliveryQuantumPolicy.Evaluate(
                QuicReceiveDeliveryQuantumObservationMode.ObserveOnly,
                forcedValue: null,
                requestedBufferLength: 64,
                lifecycleGuard: false);
        QuicReceiveDeliveryQuantumObservation observation = new(
            OperationSequence: 7,
            StreamId: 4,
            decision,
            DeliveredBytes: 16,
            SourceSegmentsRead: 2,
            Completed: true,
            BatchedReceiveCredit: true);
        Assert.True(accumulator.TryPublish(in observation));
        QuicReceiveDeliveryQuantumEpochSummary summary =
            accumulator.CaptureAndReset();

        Assert.True(summary.HasObservation);
        Assert.Equal(7UL, summary.FirstOperationSequence);
        Assert.Equal(7UL, summary.LastOperationSequence);
        Assert.Equal(1U, summary.OperationCount);
        Assert.Equal(16UL, summary.DeliveredBytes);
        Assert.Equal(2UL, summary.SourceSegmentsRead);
        Assert.Equal(1U, summary.CompletedOperationCount);
        Assert.Equal(1U, summary.BatchedReceiveCreditOperationCount);

        JsonSerializerOptions jsonOptions =
            new(JsonSerializerDefaults.Web);
        jsonOptions.Converters.Add(new JsonStringEnumConverter());
        string repoRoot =
            AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"receive-delivery-schema-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        try
        {
            string epochPath = Path.Combine(
                temporaryDirectory,
                "receive-delivery-epoch.json");
            string rawPath = Path.Combine(
                temporaryDirectory,
                "receive-delivery-raw.json");
            File.WriteAllText(
                epochPath,
                JsonSerializer.Serialize(summary, jsonOptions));
            File.WriteAllText(
                rawPath,
                JsonSerializer.Serialize(
                    new
                    {
                        schemaVersion =
                            "quic-receive-delivery-quantum-raw-v1",
                        connectionKey = "connection-0001",
                        observation,
                    },
                    jsonOptions));
            string epochSchema = Path.Combine(
                repoRoot,
                "schemas",
                "adaptive-runtime-receive-delivery-quantum-epoch-v1.schema.json");
            string rawSchema = Path.Combine(
                repoRoot,
                "schemas",
                "adaptive-runtime-receive-delivery-quantum-raw-v1.schema.json");
            string command =
                $"$epochValid = Get-Content -LiteralPath "
                + $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(epochPath)} "
                + "-Raw | Test-Json -SchemaFile "
                + $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(epochSchema)}; "
                + "$rawValid = Get-Content -LiteralPath "
                + $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(rawPath)} "
                + "-Raw | Test-Json -SchemaFile "
                + $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(rawSchema)}; "
                + "if (-not ($epochValid -and $rawValid)) { exit 1 }";
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
    public void ListenerOptionCopyPreservesReceiveDeliveryForceAndEvidence()
    {
        RecordingReceiveDeliverySink sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            ForcedReceiveDeliveryQuantumPolicyValue =
                QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
            ReceiveDeliveryQuantumObservationMode =
                QuicReceiveDeliveryQuantumObservationMode.Shadow,
            ReceiveDeliveryQuantumEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(
            selectedOptions,
            returnedOptions);

        Assert.Equal(
            QuicReceiveDeliveryQuantumPolicyValue.SingleSegment,
            selectedOptions.ForcedReceiveDeliveryQuantumPolicyValue);
        Assert.Equal(
            QuicReceiveDeliveryQuantumObservationMode.Shadow,
            selectedOptions.ReceiveDeliveryQuantumObservationMode);
        Assert.Same(sink, selectedOptions.ReceiveDeliveryQuantumEvidenceSink);
    }

    private static QuicStreamFrame ParseStreamFrame(
        ulong streamId,
        ReadOnlySpan<byte> payload,
        ulong offset)
    {
        byte frameType = QuicStreamFrameBits.StreamFrameTypeMinimum
            | QuicStreamFrameBits.LengthBitMask;
        if (offset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        byte[] encoded = new byte[payload.Length + 32];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            frameType,
            streamId,
            offset,
            payload,
            encoded,
            out int bytesWritten));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            encoded.AsSpan(0, bytesWritten),
            out QuicStreamFrame frame));
        return frame;
    }

    private sealed class RecordingReceiveDeliverySink :
        IQuicReceiveDeliveryQuantumEvidenceSink
    {
        internal List<QuicReceiveDeliveryQuantumObservation> Observations
            { get; } = [];

        public bool TryPublish(
            in QuicReceiveDeliveryQuantumObservation observation)
        {
            Observations.Add(observation);
            return true;
        }
    }

    private sealed class ThrowingReceiveDeliverySink :
        IQuicReceiveDeliveryQuantumEvidenceSink
    {
        public bool TryPublish(
            in QuicReceiveDeliveryQuantumObservation observation)
            => throw new InvalidOperationException("diagnostic");
    }
}

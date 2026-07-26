// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0219")]
[Requirement("REQ-QUIC-CRT-0220")]
[Requirement("REQ-QUIC-CRT-0221")]
[Requirement("REQ-QUIC-CRT-0222")]
public sealed class REQ_QUIC_CRT_0219
{
    private const string CaptureRootVariable =
        "INCURSA_ADAPTIVE_RUNTIME_ACTUATION_CAPTURE_ROOT";
    private const string CaptureGenerationVariable =
        "INCURSA_ADAPTIVE_RUNTIME_ACTUATION_CAPTURE_GENERATION";

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FocusedHarnessProducesIndependentMechanismCaptures()
    {
        object batch = CreateBatchCapture();
        object buffer = CreateBufferCapture();

        string? outputRoot = Environment.GetEnvironmentVariable(
            CaptureRootVariable);
        if (!string.IsNullOrWhiteSpace(outputRoot))
        {
            Directory.CreateDirectory(outputRoot);
            JsonSerializerOptions options = new()
            {
                WriteIndented = false,
            };
            File.WriteAllText(
                Path.Combine(outputRoot, "batch.raw.json"),
                JsonSerializer.Serialize(batch, options));
            File.WriteAllText(
                Path.Combine(outputRoot, "buffer.raw.json"),
                JsonSerializer.Serialize(buffer, options));
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TerminalRuntimeClampsBatchSelectionBeforeScheduler()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();
        runtime.ConfigureApplicationSendBatchPolicyMode(
            QuicApplicationSendBatchPolicyMode.SingleEligible);

        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            runtime.ApplicationSendBatchPolicyMode);

        runtime.Dispose();

        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            runtime.ApplicationSendBatchPolicyMode);
    }

    private static object CreateBatchCapture()
    {
        object[] operations =
        [
            CaptureBatchOperation(
                "connection.batch.positive",
                "positive_actuation",
                planSequence: 101,
                mode: QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: true,
                forcedValue:
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                legalWriteBytes: [100, 100, 100, 100],
                result: "applied",
                fallbackReason: null),
            CaptureBatchOperation(
                "connection.batch.inactive",
                "structurally_inactive",
                planSequence: 102,
                mode: QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: true,
                forcedValue:
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                legalWriteBytes: [80],
                result: "inactive",
                fallbackReason: "eligible_count_one"),
            CaptureBatchOperation(
                "connection.batch.fallback",
                "safety_fallback",
                planSequence: 103,
                mode: QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: true,
                forcedValue:
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                legalWriteBytes: [100, 100, 100],
                result: "clamped",
                fallbackReason: "lifecycle_guard",
                forceLifecycleGuard: true),
            CaptureBatchOperation(
                "connection.batch.shadow",
                "shadow_neutrality",
                planSequence: 104,
                mode: QuicApplicationSendBatchObservationMode.Shadow,
                hasForcedValue: false,
                forcedValue:
                    QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                legalWriteBytes: [100, 100, 100],
                result: "applied",
                fallbackReason: null,
                forceShadowRecommendation: true),
            CaptureBatchOperation(
                "connection.batch.rollback",
                "rollback",
                planSequence: 105,
                mode: QuicApplicationSendBatchObservationMode.ObserveOnly,
                hasForcedValue: false,
                forcedValue:
                    QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                legalWriteBytes: [100, 100, 100, 100],
                result: "applied",
                fallbackReason: null),
        ];

        JsonElement positive = ToElement(operations[0]);
        Assert.Equal(4, positive.GetProperty("legal_work_count").GetInt32());
        Assert.Equal(1, positive.GetProperty("applied_work_count").GetInt32());
        Assert.Equal(
            "mechanism_event.batch_single_eligible",
            positive.GetProperty("mechanism_event_id").GetString());
        JsonElement inactive = ToElement(operations[1]);
        Assert.Equal(
            "structurally_inactive",
            inactive.GetProperty("operation_eligibility_reason").GetString());
        JsonElement fallback = ToElement(operations[2]);
        Assert.Equal(
            "legacy_current",
            fallback.GetProperty("applied_value").GetString());
        JsonElement shadow = ToElement(operations[3]);
        Assert.Equal(
            "single_eligible",
            shadow.GetProperty("shadow_recommendation").GetString());
        Assert.Equal(
            "legacy_current",
            shadow.GetProperty("applied_value").GetString());
        JsonElement rollback = ToElement(operations[4]);
        Assert.Equal(4, rollback.GetProperty("applied_work_count").GetInt32());

        return NewRawCapture(
            WithCaptureGeneration(
                "mechanism_capture.batch.single_eligible"),
            "application_send_batch_formation",
            "single_eligible",
            WithCaptureGeneration(
                "run.batch.single_eligible.candidate"),
            WithCaptureGeneration(
                "binary.independent_actuation_proof"),
            operations,
            []);
    }

    private static object CreateBufferCapture()
    {
        (object Operation, object Release) positive =
            CaptureBufferRuntimeOperation(
                "connection.buffer.positive",
                "positive_actuation",
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                legalSourceSegments: 4,
                legalBytes: 400,
                appliedBytes: 200);
        (object Operation, object Release) inactive =
            CaptureBufferRuntimeOperation(
                "connection.buffer.inactive",
                "structurally_inactive",
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                legalSourceSegments: 2,
                legalBytes: 200,
                appliedBytes: 200);
        (object Operation, object Release) fallback =
            CaptureBufferRuntimeOperation(
                "connection.buffer.fallback",
                "safety_fallback",
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                legalSourceSegments: 4,
                legalBytes: 400,
                appliedBytes: 400,
                validity: QuicBufferCopyValidity.StaleRequiredInput);
        (object Operation, object Release) shadow =
            CaptureBufferRuntimeOperation(
                "connection.buffer.shadow",
                "shadow_neutrality",
                QuicBufferCopyObservationMode.Shadow,
                forcedValue: null,
                legalSourceSegments: 4,
                legalBytes: 400,
                appliedBytes: 400);
        (object Operation, object Release) rollback =
            CaptureBufferRuntimeOperation(
                "connection.buffer.rollback",
                "rollback",
                QuicBufferCopyObservationMode.ObserveOnly,
                forcedValue: null,
                legalSourceSegments: 4,
                legalBytes: 400,
                appliedBytes: 400);

        object[] operations =
        [
            positive.Operation,
            inactive.Operation,
            fallback.Operation,
            shadow.Operation,
            rollback.Operation,
        ];
        object[] releases =
        [
            positive.Release,
            inactive.Release,
            fallback.Release,
            shadow.Release,
            rollback.Release,
        ];

        JsonElement positiveElement = ToElement(positive.Operation);
        Assert.Equal(
            "mechanism_event.buffer_two_source_cap",
            positiveElement.GetProperty("mechanism_event_id").GetString());
        Assert.Equal(
            2,
            positiveElement.GetProperty("applied_work_count").GetInt32());
        JsonElement positiveRelease = ToElement(positive.Release);
        Assert.Equal(
            positiveElement.GetProperty("decision_instance_id").GetInt64(),
            positiveRelease.GetProperty("decision_instance_id").GetInt64());
        Assert.Equal(
            positiveElement.GetProperty("operation_id").GetInt64(),
            positiveRelease.GetProperty("operation_id").GetInt64());
        Assert.Equal(
            1,
            positiveRelease.GetProperty("release_count").GetInt32());
        JsonElement fallbackElement = ToElement(fallback.Operation);
        Assert.Equal(
            "legacy_current",
            fallbackElement.GetProperty("applied_value").GetString());
        JsonElement shadowElement = ToElement(shadow.Operation);
        Assert.Equal(
            "memory_conservative",
            shadowElement.GetProperty("shadow_recommendation").GetString());
        Assert.Equal(
            "legacy_current",
            shadowElement.GetProperty("applied_value").GetString());

        return NewRawCapture(
            WithCaptureGeneration(
                "mechanism_capture.buffer.memory_conservative"),
            "buffer_copy_coalescing",
            "memory_conservative",
            WithCaptureGeneration(
                "run.buffer.memory_conservative.candidate"),
            WithCaptureGeneration(
                "binary.independent_actuation_proof"),
            operations,
            releases);
    }

    internal static object CaptureBatchOperation(
        string connectionKey,
        string captureCase,
        ulong planSequence,
        QuicApplicationSendBatchObservationMode mode,
        bool hasForcedValue,
        QuicApplicationSendBatchPolicyMode forcedValue,
        int[] legalWriteBytes,
        string result,
        string? fallbackReason,
        bool forceShadowRecommendation = false,
        bool forceLifecycleGuard = false)
    {
        QuicApplicationSendPlan legalPlan = CreateBatchPlan(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            legalWriteBytes);
        QuicApplicationSendBatchObservation observation =
            CreateBatchObservation(planSequence, in legalPlan);
        if (forceShadowRecommendation)
        {
            observation = observation with
            {
                MissingSignalMask =
                    QuicApplicationSendBatchSignalMask.MaximumPayloadBytes,
            };
        }
        if (forceLifecycleGuard)
        {
            observation = observation with
            {
                LifecycleFlags = QuicAdaptiveRuntimeLifecycle.Terminal,
            };
        }

        QuicAdaptiveRuntimeStage1AxisDecision decision =
            QuicApplicationSendBatchPolicy.Evaluate(
                in observation,
                mode,
                hasForcedValue,
                forcedValue,
                in legalPlan);
        QuicApplicationSendPlan plan = CreateBatchPlan(
            BatchMode(decision.AppliedValue),
            legalWriteBytes);
        QuicApplicationSendBatchOperationEvidence evidence =
            QuicApplicationSendBatchPolicy.CreateOperationEvidence(
                epochSequence: 1,
                in observation,
                in decision,
                in plan);

        return new
        {
            connection_key = connectionKey,
            epoch_sequence = evidence.EpochSequence,
            decision_instance_id = evidence.DecisionInstanceSequence,
            operation_id = evidence.OperationSequence,
            configured_value = "legacy_current",
            forced_value = hasForcedValue ? BatchValue(forcedValue) : null,
            shadow_recommendation = decision.HasShadowRecommendation
                ? BatchValue(decision.ShadowRecommendation)
                : null,
            candidate_value = BatchValue(evidence.CandidateValue),
            operation_eligibility_result =
                Eligibility(evidence.EligibilityResult),
            operation_eligibility_reason =
                EligibilityReason(evidence.EligibilityReason),
            applied_value = BatchValue(decision.AppliedValue),
            operation_kind = "packet_plan",
            mechanism_event_id = BatchEvent(evidence.MechanismEvent),
            legal_work_count = evidence.LegalWriteCount,
            applied_work_count = evidence.AppliedWriteCount,
            legal_bytes = evidence.LegalWriteBytes,
            applied_bytes = evidence.AppliedWriteBytes,
            legal_order_keys = CreateOrderKeys(evidence.LegalWriteCount),
            applied_order_keys = CreateOrderKeys(evidence.AppliedWriteCount),
            result,
            fallback_or_safety_reason = fallbackReason,
            terminal_outcome = plan.Kind == QuicApplicationSendPlanKind.None
                ? "packet_plan_abandoned"
                : "packet_plan_committed",
            capture_case = captureCase,
        };
    }

    internal static (object Operation, object Release)
        CaptureBufferRuntimeOperation(
            string connectionKey,
            string captureCase,
            QuicBufferCopyObservationMode mode,
            QuicBufferCopyPolicyValue? forcedValue,
            int legalSourceSegments,
            int legalBytes,
            int appliedBytes,
            QuicBufferCopyValidity validity = QuicBufferCopyValidity.None,
            QuicAdaptiveRuntimeCorrectnessInteractionAuthorization?
                interactionAuthorization = null)
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();
        RecordingBufferEvidenceSink sink = new();
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ForcedReceiveCreditPolicyMode =
                    QuicReceiveCreditPolicyMode.LegacyCurrent,
                ForcedApplicationSendBatchPolicyMode =
                    interactionAuthorization is null
                        ? null
                        : QuicApplicationSendBatchPolicyMode.SingleEligible,
                AdaptiveRuntimeShadowEnabled = true,
                AdaptiveRuntimeShadowEpochInterval =
                    TimeSpan.FromMilliseconds(250),
                AdaptiveRuntimeShadowEpochSink =
                    new RecordingShadowEpochSink(),
                ForcedBufferCopyPolicyValue = forcedValue,
                BufferCopyObservationMode = mode,
                BufferCopyEvidenceSink = sink,
                SendCompositionCorrectnessAuthorization =
                    interactionAuthorization,
            });

        QuicBufferCopyPolicyDecision decision = QuicBufferCopyPolicy.Evaluate(
            mode,
            forcedValue,
            legalSourceSegments,
            validity,
            lifecycleGuard: false);
        int appliedSourceSegments = decision.AppliedSourceSegmentCount;
        QuicBufferCopyLifetimeToken token =
            runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.CombinedApplicationSend,
            QuicBufferCopyOperation.Combine,
            QuicBufferCopyDecisionBoundary.PacketPlan,
            joinOperationSequence: null,
            legalLogicalBytes: legalBytes,
            logicalBytes: appliedBytes,
            copiedBytes: appliedBytes,
            legalSourceSegmentCount: legalSourceSegments,
            sourceSegmentCount: appliedSourceSegments,
            requestedCapacityBytes: appliedBytes,
            retainedCapacityBytes: appliedBytes,
            in decision,
            trackTerminalRelease: true,
            ownerRented: true);
        Assert.False(token.IsEmpty);
        QuicBufferCopyObservation observation = Assert.Single(sink.Copies);
        QuicBufferCopyCoalescingOperationEvidence evidence =
            observation.CoalescingEvidence;
        Assert.Equal((uint)appliedSourceSegments, evidence.AppliedSourceSegmentCount);
        ((IQuicBufferCopyOperationObserver)runtime).ObserveBufferRelease(
            in token,
            QuicBufferReleaseReason.Canceled,
            appliedBytes);
        QuicBufferReleaseObservation release = Assert.Single(sink.Releases);

        string result = captureCase switch
        {
            "structurally_inactive" => "inactive",
            "safety_fallback" => "clamped",
            _ => "applied",
        };
        string? fallbackReason = captureCase switch
        {
            "structurally_inactive" => "source_segment_count_within_cap",
            "safety_fallback" =>
                EligibilityReason(evidence.EligibilityReason),
            _ => null,
        };
        object operation = new
        {
            connection_key = connectionKey,
            epoch_sequence = evidence.EpochSequence,
            decision_instance_id = evidence.DecisionInstanceSequence,
            operation_id = evidence.OperationSequence,
            configured_value = "legacy_current",
            forced_value = observation.ForcedValue.HasValue
                ? BufferValue(observation.ForcedValue.Value)
                : null,
            shadow_recommendation = observation.ShadowRecommendation.HasValue
                ? BufferValue(observation.ShadowRecommendation.Value)
                : null,
            candidate_value = BufferValue(evidence.CandidateValue),
            operation_eligibility_result =
                Eligibility(evidence.EligibilityResult),
            operation_eligibility_reason =
                EligibilityReason(evidence.EligibilityReason),
            applied_value = BufferValue(observation.AppliedValue),
            operation_kind = "combined_send",
            mechanism_event_id = BufferEvent(evidence.MechanismEvent),
            legal_work_count = evidence.LegalSourceSegmentCount,
            applied_work_count = evidence.AppliedSourceSegmentCount,
            legal_bytes = evidence.LegalBytes,
            applied_bytes = evidence.AppliedBytes,
            legal_order_keys =
                CreateOrderKeys(evidence.LegalSourceSegmentCount),
            applied_order_keys =
                CreateOrderKeys(evidence.AppliedSourceSegmentCount),
            result,
            fallback_or_safety_reason = fallbackReason,
            terminal_outcome = "released",
            capture_case = captureCase,
        };
        object releaseRecord = new
        {
            connection_key = connectionKey,
            operation_epoch_sequence = evidence.EpochSequence,
            decision_epoch_sequence = release.DecisionEpochSequence,
            release_epoch_sequence = release.ReleaseEpochSequence,
            decision_instance_id = release.DecisionInstanceSequence,
            operation_id = release.OperationSequence,
            release_count = 1,
            terminal_outcome = "released",
            release_reason = BufferReleaseReason(release.Reason),
            validity = BufferReleaseValidity(release.Validity),
        };
        return (operation, releaseRecord);
    }

    private static object NewRawCapture(
        string documentId,
        string axisId,
        string policyValue,
        string runId,
        string binaryCohortId,
        object[] operations,
        object[] releases)
        => new
        {
            schema_version =
                "adaptive-runtime-actuation-mechanism-capture-v1",
            document_id = documentId,
            document_version = 1,
            content_sha256 = new string('0', 64),
            axis_id = axisId,
            policy_value = policyValue,
            harness_id =
                "incursa.quic.tests.req-quic-crt-0219.focused-mechanism",
            capture_mode = "focused_correctness_mechanism_harness",
            run_id = runId,
            binary_cohort_id = binaryCohortId,
            forced_behavior_distinct_axis_count = 1,
            operations,
            releases,
            active_behavior_authorization = false,
            performance_acceptance_authorization = false,
            trace_references = new
            {
                requirement_ids = new[]
                {
                    "REQ-QUIC-CRT-0218",
                    "REQ-QUIC-CRT-0219",
                    "REQ-QUIC-CRT-0220",
                    "REQ-QUIC-CRT-0221",
                    "REQ-QUIC-CRT-0222",
                },
                architecture_ids = new[] { "ARC-QUIC-CRT-0104" },
                work_item_ids = new[] { "WI-QUIC-CRT-0105" },
                verification_ids = new[] { "VER-QUIC-CRT-0106" },
            },
        };

    private static QuicApplicationSendPlan CreateBatchPlan(
        QuicApplicationSendBatchPolicyMode mode,
        int[] legalWriteBytes)
    {
        int selectedWriteCount =
            QuicApplicationSendBatchPolicy.SelectWriteCount(
                mode,
                legalWriteBytes.Length);
        int eligibleWriteBytes = legalWriteBytes.Sum();
        int selectedWriteBytes =
            legalWriteBytes.AsSpan(0, selectedWriteCount).ToArray().Sum();
        return new(
            selectedWriteCount == 1
                ? QuicApplicationSendPlanKind.SingleWrite
                : QuicApplicationSendPlanKind.Batch,
            selectedWriteCount,
            FragmentDataLength: 0,
            HasMoreQueuedData: selectedWriteCount < legalWriteBytes.Length,
            QuicSendPolicyBlockedReason.None,
            FirstStreamId: 0,
            mode,
            legalWriteBytes.Length,
            eligibleWriteBytes,
            selectedWriteBytes);
    }

    private static string[] CreateOrderKeys(uint count)
        => Enumerable.Range(0, checked((int)count))
            .Select(static value => $"work.{value:D4}")
            .ToArray();

    private static QuicApplicationSendBatchPolicyMode BatchMode(
        QuicAdaptiveRuntimeStage1PolicyValue value)
        => value switch
        {
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent =>
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible =>
                QuicApplicationSendBatchPolicyMode.SingleEligible,
            _ => throw new ArgumentOutOfRangeException(nameof(value)),
        };

    private static QuicApplicationSendBatchObservation CreateBatchObservation(
        ulong planSequence,
        in QuicApplicationSendPlan plan)
        => new(
            planSequence,
            CapturedAtTicks: 1,
            QuicApplicationSendBatchObservation.CurrentObservationContractVersion,
            QuicApplicationSendBatchObservation.CurrentRuleVersion,
            QuicApplicationSendBatchSignalMask.None,
            QuicApplicationSendBatchSignalMask.None,
            QuicApplicationSendBatchObservationCondition.None,
            QuicAdaptiveRuntimeLifecycle.None,
            MaximumPayloadBytes: 1200,
            plan.EligibleWriteCount,
            plan.EligibleWriteBytes,
            QueuedApplicationWrites: (uint)Math.Max(plan.EligibleWriteCount, 0),
            OutboundBacklogBytes: (ulong)Math.Max(plan.EligibleWriteBytes, 0),
            DistinctQueuedStreams: 1,
            OldestQueuedSendAgeMicros: 0,
            QueueDelayEwmaMicros: 0,
            ActorServiceTimeEwmaMicros: 0,
            BytesInFlight: 0,
            CongestionWindowBytes: 1200,
            RetainedSendBuffers: 0,
            RetainedSendBytes: 0);

    private static JsonElement ToElement(object value)
        => JsonSerializer.SerializeToElement(value);

    private static string WithCaptureGeneration(string value)
    {
        string? generation = Environment.GetEnvironmentVariable(
            CaptureGenerationVariable);
        if (string.IsNullOrWhiteSpace(generation))
        {
            return value;
        }

        if (generation.Any(static character =>
                !(char.IsAsciiLetterOrDigit(character)
                    || character is '_' or '-')))
        {
            throw new InvalidOperationException(
                "The actuation capture generation must be a stable identifier.");
        }

        return $"{value}.{generation.ToLowerInvariant()}";
    }

    private static string BatchValue(
        QuicApplicationSendBatchPolicyMode value)
        => value switch
        {
            QuicApplicationSendBatchPolicyMode.LegacyCurrent =>
                "legacy_current",
            QuicApplicationSendBatchPolicyMode.SingleEligible =>
                "single_eligible",
            _ => throw new ArgumentOutOfRangeException(nameof(value)),
        };

    private static string BatchValue(
        QuicAdaptiveRuntimeStage1PolicyValue value)
        => value switch
        {
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent =>
                "legacy_current",
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible =>
                "single_eligible",
            _ => throw new ArgumentOutOfRangeException(nameof(value)),
        };

    private static string BufferValue(QuicBufferCopyPolicyValue value)
        => value switch
        {
            QuicBufferCopyPolicyValue.LegacyCurrent => "legacy_current",
            QuicBufferCopyPolicyValue.MemoryConservative =>
                "memory_conservative",
            _ => throw new ArgumentOutOfRangeException(nameof(value)),
        };

    private static string Eligibility(
        QuicAdaptiveRuntimeOperationEligibilityResult value)
        => value.ToString().ToLowerInvariant();

    private static string EligibilityReason(
        QuicAdaptiveRuntimeOperationEligibilityReason value)
        => value switch
        {
            QuicAdaptiveRuntimeOperationEligibilityReason.StructurallyInactive
                => "structurally_inactive",
            QuicAdaptiveRuntimeOperationEligibilityReason.MissingInput =>
                "missing_input",
            QuicAdaptiveRuntimeOperationEligibilityReason.InvalidInput =>
                "invalid_input",
            QuicAdaptiveRuntimeOperationEligibilityReason.LifecycleGuard =>
                "lifecycle_guard",
            QuicAdaptiveRuntimeOperationEligibilityReason.ResourceGuard =>
                "resource_guard",
            QuicAdaptiveRuntimeOperationEligibilityReason.SafetyOverride =>
                "safety_override",
            QuicAdaptiveRuntimeOperationEligibilityReason.NotAxisMechanism =>
                "not_axis_mechanism",
            QuicAdaptiveRuntimeOperationEligibilityReason.UnclassifiableEvidence
                => "unclassifiable_evidence",
            _ => "eligible",
        };

    private static string BatchEvent(
        QuicApplicationSendBatchMechanismEvent value)
        => value switch
        {
            QuicApplicationSendBatchMechanismEvent.LegalEligiblePrefixUsed =>
                "mechanism_event.batch_legal_prefix",
            QuicApplicationSendBatchMechanismEvent.SingleEligiblePrefixUsed =>
                "mechanism_event.batch_single_eligible",
            QuicApplicationSendBatchMechanismEvent.NoPacketPlan =>
                "mechanism_event.batch_no_packet_plan",
            _ => "mechanism_event.batch_unclassifiable",
        };

    private static string BufferEvent(
        QuicBufferCopyCoalescingMechanismEvent value)
        => value switch
        {
            QuicBufferCopyCoalescingMechanismEvent.ExactCombinedPrefixRetained
                => "mechanism_event.buffer_legacy_prefix",
            QuicBufferCopyCoalescingMechanismEvent
                .LowerTwoSourceSegmentCapApplied =>
                "mechanism_event.buffer_two_source_cap",
            QuicBufferCopyCoalescingMechanismEvent.NoCombinedOwnerRented =>
                "mechanism_event.buffer_no_owner",
            QuicBufferCopyCoalescingMechanismEvent.NotAxisMechanism =>
                "mechanism_event.buffer_not_axis",
            _ => "mechanism_event.buffer_unclassifiable",
        };

    private static string BufferReleaseReason(QuicBufferReleaseReason value)
        => value.ToString().ToLowerInvariant();

    private static string BufferReleaseValidity(QuicBufferReleaseValidity value)
        => value == QuicBufferReleaseValidity.None
            ? "none"
            : value.ToString().ToLowerInvariant();

    private sealed class RecordingBufferEvidenceSink :
        IQuicBufferCopyEvidenceSink,
        IQuicBufferReleaseEvidenceSink
    {
        internal List<QuicBufferCopyObservation> Copies { get; } = [];

        internal List<QuicBufferReleaseObservation> Releases { get; } = [];

        public bool TryPublish(in QuicBufferCopyObservation observation)
        {
            Copies.Add(observation);
            return true;
        }

        public bool TryPublish(in QuicBufferReleaseObservation observation)
        {
            Releases.Add(observation);
            return true;
        }
    }

    private sealed class RecordingShadowEpochSink :
        IQuicAdaptiveRuntimeShadowEpochSink
    {
        public bool TryPublish(
            in QuicAdaptiveRuntimeConnectionObservation observation,
            in QuicReceiveCreditPolicySnapshot snapshot,
            in QuicAdaptiveRuntimePostServiceBoundary boundary)
            => true;
    }
}

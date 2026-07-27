// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;
using System.Text.Json;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

public sealed partial class REQ_QUIC_CRT_0238
{
    private const string RuntimeCaptureRootVariable =
        "INCURSA_ADAPTIVE_RUNTIME_FACTOR_RUNTIME_CAPTURE_ROOT";
    private const string RuntimeCaptureSourceCommitVariable =
        "INCURSA_ADAPTIVE_RUNTIME_FACTOR_SOURCE_COMMIT";
    private const string RuntimeCaptureBinaryHashVariable =
        "INCURSA_ADAPTIVE_RUNTIME_FACTOR_BINARY_SHA256";
    private const string RuntimeCaptureSessionVariable =
        "INCURSA_ADAPTIVE_RUNTIME_FACTOR_CAPTURE_SESSION_ID";

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeProofHarnessExportsOnlySinkEmittedMechanismFacts()
    {
        object single = await CaptureOversizedProofAsync(
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment);
        object bounded = await CaptureOversizedProofAsync(
            QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment);
        object queued = await CaptureQueuedProofAsync();

        string? outputRoot = Environment.GetEnvironmentVariable(
            RuntimeCaptureRootVariable);
        if (!string.IsNullOrWhiteSpace(outputRoot))
        {
            Directory.CreateDirectory(outputRoot);
            JsonSerializerOptions options = new()
            {
                WriteIndented = false,
            };
            File.WriteAllText(
                Path.Combine(outputRoot, "oversized-single.runtime.json"),
                JsonSerializer.Serialize(single, options));
            File.WriteAllText(
                Path.Combine(outputRoot, "oversized-bounded.runtime.json"),
                JsonSerializer.Serialize(bounded, options));
            File.WriteAllText(
                Path.Combine(outputRoot, "queued-single.runtime.json"),
                JsonSerializer.Serialize(queued, options));
        }
    }

    private static async Task<object> CaptureOversizedProofAsync(
        QuicOversizedWriteAdmissionPolicyMode policyValue)
    {
        QuicOversizedWriteAdmissionEvidence positive =
            await RunOversizedWriteAsync(
                policyValue,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                payloadLength: 5 * 32 * 1024,
                cancelAfterFirstTransition: false,
                forceValue: true);
        QuicOversizedWriteAdmissionEvidence inactive =
            await RunOversizedWriteAsync(
                policyValue,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                payloadLength: 800,
                cancelAfterFirstTransition: false,
                forceValue: true);
        QuicOversizedWriteAdmissionEvidence fallback =
            await RunOversizedWriteAsync(
                policyValue,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                payloadLength: 5 * 32 * 1024,
                cancelAfterFirstTransition: true,
                forceValue: true);
        QuicOversizedWriteAdmissionEvidence shadow =
            await RunOversizedWriteAsync(
                policyValue,
                QuicOversizedWriteAdmissionObservationMode.Shadow,
                payloadLength: 5 * 32 * 1024,
                cancelAfterFirstTransition: false,
                forceValue: false);
        QuicOversizedWriteAdmissionEvidence rollback =
            await RunOversizedWriteAsync(
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                QuicOversizedWriteAdmissionObservationMode.ObserveOnly,
                payloadLength: 5 * 32 * 1024,
                cancelAfterFirstTransition: false,
                forceValue: false);

        Assert.Equal(1, positive.CompletionCount);
        Assert.Equal(1, fallback.CompletionCount);
        Assert.Equal(
            QuicOversizedWriteMechanismEvent.InactiveSingleFragmentWrite,
            inactive.MechanismEvent);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            shadow.Decision.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            rollback.Decision.AppliedValue);

        return new
        {
            schema_version = "adaptive-runtime-runtime-proof-sink-export-v1",
            export_id = $"runtime_sink_export.oversized_write.{OversizedValue(policyValue)}",
            source_commit = GetCaptureBinding(
                RuntimeCaptureSourceCommitVariable,
                new string('0', 40)),
            binary_sha256 = GetCaptureBinding(
                RuntimeCaptureBinaryHashVariable,
                new string('0', 64)),
            capture_session_id = GetCaptureBinding(
                RuntimeCaptureSessionVariable,
                "runtime_capture.unbound"),
            axis_id = "oversized_write_admission_quantum",
            policy_value = OversizedValue(policyValue),
            source_kind = "quic_oversized_write_admission_evidence_sink",
            records = new[]
            {
                OversizedRecord("positive_actuation", positive),
                OversizedRecord("structurally_inactive", inactive),
                OversizedRecord("safety_fallback", fallback),
                OversizedRecord("shadow_neutrality", shadow),
                OversizedRecord("rollback", rollback),
            },
        };
    }

    private static async Task<QuicOversizedWriteAdmissionEvidence>
        RunOversizedWriteAsync(
            QuicOversizedWriteAdmissionPolicyMode policyValue,
            QuicOversizedWriteAdmissionObservationMode observationMode,
            int payloadLength,
            bool cancelAfterFirstTransition,
            bool forceValue)
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath(
                    connectionSendLimit: 2 * 1024 * 1024,
                    localBidirectionalSendLimit: 2 * 1024 * 1024);
        ConcurrentQueue<RuntimePostedStreamWrite> postedWrites = new();
        runtime.SetStreamWriteDispatcher(
            (requestId, actionKind, streamId, streamData, streamDataSuffix) =>
            {
                postedWrites.Enqueue(new RuntimePostedStreamWrite(
                    requestId,
                    actionKind,
                    streamId,
                    streamData,
                    streamDataSuffix));
                return true;
            });
        RegisterRuntimeCaptureObservers(runtime, count: 16);
        RuntimeOversizedEvidenceSink sink = new();
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedOversizedWriteAdmissionPolicyMode =
                forceValue ? policyValue : null,
            OversizedWriteAdmissionObservationMode = observationMode,
            OversizedWriteAdmissionEvidenceSink = sink,
        });
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));
        using CancellationTokenSource cancellation = new();
        Task write = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[payloadLength],
            cancellation.Token).AsTask();
        long nowTicks = 20;
        bool transitioned = false;
        while (!write.IsCompleted)
        {
            if (postedWrites.TryDequeue(out RuntimePostedStreamWrite posted))
            {
                _ = runtime.TransitionStreamWrite(
                    posted.RequestId,
                    posted.ActionKind,
                    posted.StreamId,
                    posted.StreamData,
                    posted.StreamDataSuffix,
                    nowTicks++);
                transitioned = true;
                if (cancelAfterFirstTransition)
                {
                    await cancellation.CancelAsync();
                    break;
                }

                continue;
            }

            await Task.Yield();
        }

        Assert.True(transitioned);
        if (cancelAfterFirstTransition)
        {
            await Assert.ThrowsAsync<OperationCanceledException>(
                () => write.WaitAsync(TimeSpan.FromSeconds(5)));
        }
        else
        {
            await write.WaitAsync(TimeSpan.FromSeconds(5));
        }

        return Assert.Single(sink.Evidence);
    }

    private static object OversizedRecord(
        string captureCase,
        QuicOversizedWriteAdmissionEvidence evidence)
        => new
        {
            capture_case = captureCase,
            logical_write_sequence = evidence.Observation.LogicalWriteSequence,
            runtime_request_id = evidence.RuntimeRequestId,
            decision_instance_id = evidence.Decision.DecisionSequence,
            operation_id = evidence.RuntimeRequestId > 0
                ? evidence.RuntimeRequestId
                : checked((long)evidence.Observation.LogicalWriteSequence),
            configured_value = "legacy_current",
            forced_value = evidence.Decision.HasForcedValue
                ? OversizedDecisionValue(evidence.Decision.ForcedValue)
                : null,
            shadow_recommendation = evidence.Decision.HasShadowRecommendation
                ? OversizedDecisionValue(evidence.Decision.ShadowRecommendation)
                : null,
            candidate_value = OversizedDecisionValue(
                evidence.Decision.SelectedValue),
            applied_value = OversizedDecisionValue(
                evidence.Decision.AppliedValue),
            selection_source = evidence.Decision.SelectionSource.ToString(),
            safety_override_reason =
                evidence.Decision.SafetyOverrideReason.ToString(),
            logical_write_bytes = evidence.Observation.LogicalWriteBytes,
            maximum_fragment_bytes =
                evidence.Observation.MaximumFragmentBytes,
            legal_fragment_count = DivideRoundUp(
                evidence.Observation.LogicalWriteBytes,
                evidence.Observation.MaximumFragmentBytes),
            applied_chunk_quantum = evidence.AppliedChunkQuantum,
            initial_committed_fragments =
                evidence.InitialCommittedFragments,
            initial_committed_bytes = evidence.InitialCommittedBytes,
            committed_fragments = evidence.CommittedFragments,
            committed_bytes = evidence.CommittedBytes,
            continuation_count = evidence.ContinuationCount,
            continuation_posts = evidence.ContinuationPosts,
            first_continuation_sequence =
                evidence.FirstContinuationSequence,
            continuation_request_id = evidence.ContinuationRequestId,
            completion_count = evidence.CompletionCount,
            mechanism_event = evidence.MechanismEvent.ToString(),
            terminal_outcome = evidence.Outcome.ToString(),
            observation_contract_version =
                evidence.Observation.ObservationContractVersion,
            rule_version = evidence.Observation.RuleVersion,
        };

    private static async Task<object> CaptureQueuedProofAsync()
    {
        QuicQueuedSendBurstEvidence positive =
            await RunQueuedSendBurstAsync(
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                forceValue: true,
                queuedWriteCount: 48,
                connectionSendLimit: 16_384,
                triggerWithAck: true);
        QuicQueuedSendBurstEvidence inactive =
            await RunQueuedSendBurstAsync(
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                forceValue: true,
                queuedWriteCount: 1,
                connectionSendLimit: 16_384,
                triggerWithAck: true);
        QuicQueuedSendBurstEvidence fallback =
            await RunQueuedSendBurstAsync(
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                forceValue: true,
                queuedWriteCount: 8,
                connectionSendLimit: 16_384,
                triggerWithAck: false);
        QuicQueuedSendBurstEvidence shadow =
            await RunQueuedSendBurstAsync(
                QuicQueuedSendBurstPolicyMode.SingleDatagram,
                forceValue: false,
                queuedWriteCount: 48,
                connectionSendLimit: 16_384,
                triggerWithAck: true);
        QuicQueuedSendBurstEvidence rollback =
            await RunQueuedSendBurstAsync(
                QuicQueuedSendBurstPolicyMode.LegacyCurrent,
                forceValue: false,
                queuedWriteCount: 48,
                connectionSendLimit: 16_384,
                triggerWithAck: true);

        Assert.Equal(1, positive.EmittedDatagrams);
        Assert.True(positive.FollowOnWakeRequired);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            shadow.Decision.ShadowRecommendation);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            shadow.Decision.AppliedValue);

        return new
        {
            schema_version = "adaptive-runtime-runtime-proof-sink-export-v1",
            export_id = "runtime_sink_export.queued_send.single_datagram",
            source_commit = GetCaptureBinding(
                RuntimeCaptureSourceCommitVariable,
                new string('0', 40)),
            binary_sha256 = GetCaptureBinding(
                RuntimeCaptureBinaryHashVariable,
                new string('0', 64)),
            capture_session_id = GetCaptureBinding(
                RuntimeCaptureSessionVariable,
                "runtime_capture.unbound"),
            axis_id = "queued_send_burst_budget",
            policy_value = "single_datagram",
            source_kind = "quic_queued_send_burst_evidence_sink",
            records = new[]
            {
                QueuedRecord("positive_actuation", positive),
                QueuedRecord("structurally_inactive", inactive),
                QueuedRecord("safety_fallback", fallback),
                QueuedRecord("shadow_neutrality", shadow),
                QueuedRecord("rollback", rollback),
            },
        };
    }

    private static async Task<QuicQueuedSendBurstEvidence>
        RunQueuedSendBurstAsync(
            QuicQueuedSendBurstPolicyMode policyValue,
            bool forceValue,
            int queuedWriteCount,
            ulong connectionSendLimit,
            bool triggerWithAck)
    {
        QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateConfirmedClientRuntimeWithValidatedActivePath(
                    connectionSendLimit: connectionSendLimit,
                    localBidirectionalSendLimit: 16_384);
        Queue<RuntimePostedStreamWrite> postedWrites = new();
        runtime.SetStreamWriteDispatcher(
            (requestId, actionKind, streamId, streamData, streamDataSuffix) =>
            {
                postedWrites.Enqueue(new RuntimePostedStreamWrite(
                    requestId,
                    actionKind,
                    streamId,
                    streamData,
                    streamDataSuffix));
                return true;
            });
        RuntimeQueuedEvidenceSink sink = new();
        try
        {
            runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
            {
                AdaptiveRuntimeShadowEnabled = true,
                ForcedQueuedSendBurstPolicyMode =
                    forceValue ? policyValue : null,
                QueuedSendBurstObservationMode =
                    QuicQueuedSendBurstObservationMode.Shadow,
                QueuedSendBurstEvidenceSink = sink,
            });
            Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId streamId,
                out _));
            Task direct = runtime.WriteStreamAsync(
                streamId.Value,
                new byte[800],
                CancellationToken.None).AsTask();
            RuntimePostedStreamWrite directPosted = Assert.Single(postedWrites);
            _ = postedWrites.Dequeue();
            _ = runtime.TransitionStreamWrite(
                directPosted.RequestId,
                directPosted.ActionKind,
                directPosted.StreamId,
                directPosted.StreamData,
                directPosted.StreamDataSuffix,
                nowTicks: 10);
            await direct.WaitAsync(TimeSpan.FromSeconds(5));
            ulong largestAcknowledged = runtime.SendRuntime.SentPackets.Keys
                .Where(static key =>
                    key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
                .Max(static key => key.PacketNumber);
            for (int index = 0; index < queuedWriteCount; index++)
            {
                Task write = runtime.WriteStreamAsync(
                    streamId.Value,
                    new byte[31],
                    CancellationToken.None).AsTask();
                RuntimePostedStreamWrite posted = Assert.Single(postedWrites);
                _ = postedWrites.Dequeue();
                _ = runtime.TransitionStreamWrite(
                    posted.RequestId,
                    posted.ActionKind,
                    posted.StreamId,
                    posted.StreamData,
                    posted.StreamDataSuffix,
                    nowTicks: 20);
                await write.WaitAsync(TimeSpan.FromSeconds(5));
            }

            if (triggerWithAck)
            {
                _ = QuicS13AckPiggybackTestSupport.ReceiveOneRttAckOnly(
                    runtime,
                    observedAtTicks: 100,
                    packetNumber: 1,
                    largestAcknowledged);
            }
            else
            {
                QuicCongestionControlState congestion =
                    runtime.SendRuntime.FlowController.CongestionControlState;
                ulong blockedBytesInFlight =
                    congestion.CongestionWindowBytes + 800;
                if (congestion.BytesInFlightBytes < blockedBytesInFlight)
                {
                    congestion.RegisterPacketSent(
                        blockedBytesInFlight
                        - congestion.BytesInFlightBytes);
                }

                _ = QuicS13AckPiggybackTestSupport.ReceiveOneRttAckOnly(
                    runtime,
                    observedAtTicks: 100,
                    packetNumber: 1,
                    largestAcknowledged);
            }

            return Assert.Single(sink.Evidence);
        }
        finally
        {
            await runtime.DisposeAsync();
        }
    }

    private static object QueuedRecord(
        string captureCase,
        QuicQueuedSendBurstEvidence evidence)
        => new
        {
            capture_case = captureCase,
            actor_turn_sequence = evidence.Observation.TurnSequence,
            decision_instance_id = evidence.Decision.DecisionSequence,
            operation_id = checked((long)evidence.Observation.TurnSequence),
            configured_value = "legacy_current",
            forced_value = evidence.Decision.HasForcedValue
                ? QueuedDecisionValue(evidence.Decision.ForcedValue)
                : null,
            shadow_recommendation = evidence.Decision.HasShadowRecommendation
                ? QueuedDecisionValue(evidence.Decision.ShadowRecommendation)
                : null,
            candidate_value = QueuedDecisionValue(
                evidence.Decision.SelectedValue),
            applied_value = QueuedDecisionValue(
                evidence.Decision.AppliedValue),
            selection_source = evidence.Decision.SelectionSource.ToString(),
            safety_override_reason =
                evidence.Decision.SafetyOverrideReason.ToString(),
            legal_maximum_datagrams = evidence.LegalMaximumDatagrams,
            applied_maximum_datagrams = evidence.AppliedMaximumDatagrams,
            emitted_datagrams = evidence.EmittedDatagrams,
            queued_writes_before = evidence.QueuedWritesBefore,
            queued_writes_after = evidence.QueuedWritesAfter,
            queued_bytes_before = evidence.QueuedBytesBefore,
            queued_bytes_after = evidence.QueuedBytesAfter,
            follow_on_wake_required = evidence.FollowOnWakeRequired,
            follow_on_wake_due_ticks = evidence.FollowOnWakeDueTicks,
            follow_on_wake_generation = evidence.FollowOnWakeGeneration,
            outcome = evidence.Outcome.ToString(),
            blocked_reason = evidence.BlockedReason.ToString(),
            observation_contract_version =
                evidence.Observation.ObservationContractVersion,
            rule_version = evidence.Observation.RuleVersion,
        };

    private static string GetCaptureBinding(
        string variable,
        string unboundValue)
    {
        string? value = Environment.GetEnvironmentVariable(variable);
        return string.IsNullOrWhiteSpace(value) ? unboundValue : value;
    }

    private static string OversizedValue(
        QuicOversizedWriteAdmissionPolicyMode value)
        => value switch
        {
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent =>
                "legacy_current",
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment =>
                "single_fragment",
            QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment =>
                "bounded_multi_fragment",
            _ => throw new ArgumentOutOfRangeException(nameof(value)),
        };

    private static string OversizedDecisionValue(
        QuicAdaptiveRuntimeStage1PolicyValue value)
        => value switch
        {
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent =>
                "legacy_current",
            QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment =>
                "single_fragment",
            QuicAdaptiveRuntimeStage1PolicyValue.BoundedMultiFragment =>
                "bounded_multi_fragment",
            _ => value.ToString(),
        };

    private static string QueuedDecisionValue(
        QuicAdaptiveRuntimeStage1PolicyValue value)
        => value switch
        {
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent =>
                "legacy_current",
            QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram =>
                "single_datagram",
            _ => value.ToString(),
        };

    private static int DivideRoundUp(int value, int divisor)
        => checked((value + divisor - 1) / divisor);

    private static void RegisterRuntimeCaptureObservers(
        QuicConnectionRuntime runtime,
        int count)
    {
        for (int index = 0; index < count; index++)
        {
            _ = runtime.RegisterStreamObserver(
                (ulong)(index * 4),
                static _ => { });
        }
    }

    private readonly record struct RuntimePostedStreamWrite(
        long RequestId,
        QuicConnectionStreamActionKind ActionKind,
        ulong StreamId,
        ReadOnlyMemory<byte> StreamData,
        ReadOnlyMemory<byte> StreamDataSuffix);

    private sealed class RuntimeOversizedEvidenceSink :
        IQuicOversizedWriteAdmissionEvidenceSink
    {
        internal List<QuicOversizedWriteAdmissionEvidence> Evidence { get; } = [];

        public bool TryPublish(
            in QuicOversizedWriteAdmissionEvidence evidence)
        {
            Evidence.Add(evidence);
            return true;
        }
    }

    private sealed class RuntimeQueuedEvidenceSink :
        IQuicQueuedSendBurstEvidenceSink
    {
        internal List<QuicQueuedSendBurstEvidence> Evidence { get; } = [];

        public bool TryPublish(in QuicQueuedSendBurstEvidence evidence)
        {
            Evidence.Add(evidence);
            return true;
        }
    }
}

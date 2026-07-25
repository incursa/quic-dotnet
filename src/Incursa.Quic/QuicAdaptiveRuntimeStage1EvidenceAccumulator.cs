// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicAdaptiveRuntimeStage1OutcomeScope : byte
{
    Epoch = 0,
    Operation = 1,
    Plan = 2,
    ActorTurn = 3,
}

internal readonly record struct QuicAdaptiveRuntimeStage1ObservationValues(
    ulong? QueuedApplicationWrites,
    ulong? OutboundBacklogBytes,
    ulong? DistinctQueuedSendStreams,
    ulong? OldestQueuedSendAgeMicros,
    ulong? QueueDelayEwmaMicros,
    ulong? ActorServiceTimeEwmaMicros,
    ulong? MaximumPayloadBytes,
    ulong? EligibleWriteCount,
    ulong? EligibleWriteBytes,
    ulong? LegalMaximumDatagrams,
    ulong? ConfiguredMaximumDatagrams,
    ulong? BurstLimitHits,
    ulong? LogicalWriteRemainingBytes,
    ulong? MaximumChunkBytes,
    ulong? RetainedSendBuffers,
    ulong? RetainedSendBytes,
    ulong? BytesInFlight,
    ulong? CongestionWindowBytes,
    bool? HandshakeConfirmed,
    bool? CancellationRequested,
    bool? DisposalStarted,
    bool? TerminalStarted);

internal readonly record struct QuicAdaptiveRuntimeStage1EpochOutcomes(
    QuicAdaptiveRuntimeStage1OutcomeScope Scope,
    ulong? SelectedWriteCount,
    ulong? SelectedPayloadBytes,
    ulong? AppliedDatagramCap,
    ulong? EmittedDatagrams,
    ulong? AdmittedFragments,
    ulong? ContinuationCount,
    ulong CompletedOperations,
    QuicApplicationSendBatchBehaviorEpochCounts BatchBehaviorCounts);

internal readonly record struct QuicAdaptiveRuntimeStage1EpochAxisRecord(
    QuicAdaptiveRuntimeStage1AxisDecision Decision,
    QuicAdaptiveRuntimeStage1ObservationValues ObservationValues,
    QuicAdaptiveRuntimeStage1EpochOutcomes Outcomes,
    ulong EventCount,
    bool HasEvent);

internal readonly record struct QuicAdaptiveRuntimeStage1EpochEvidence(
    ulong EpochIndex,
    ulong EpochStartOffsetMicros,
    ulong EpochDurationMicros,
    QuicAdaptiveRuntimeStage1PolicySnapshot PolicySnapshot,
    QuicAdaptiveRuntimeStage1EpochAxisRecord ApplicationSendTurnPlanning,
    QuicAdaptiveRuntimeStage1EpochAxisRecord ApplicationSendBatchFormation,
    QuicAdaptiveRuntimeStage1EpochAxisRecord QueuedSendBurstBudget,
    QuicAdaptiveRuntimeStage1EpochAxisRecord OversizedWriteAdmissionQuantum);

/// <summary>
/// Collects bounded, connection-local Stage 1 evidence. Policy-specific
/// operation records remain owned by their original sinks; this type only
/// produces the four-axis epoch summary used by the unified evidence plane.
/// </summary>
internal sealed class QuicAdaptiveRuntimeStage1EvidenceAccumulator :
    IQuicApplicationSendTurnEvidenceSink,
    IQuicApplicationSendBatchEvidenceSink,
    IQuicQueuedSendBurstEvidenceSink,
    IQuicOversizedWriteAdmissionEvidenceSink
{
    private readonly object sync = new();
    private readonly QuicAdaptiveRuntimeStage1PolicySnapshot configuredPolicy;
    private AxisState sendTurn;
    private AxisState sendBatch;
    private AxisState burstBudget;
    private AxisState oversizedWrite;
    private ulong lastEpochIndex;

    internal QuicAdaptiveRuntimeStage1EvidenceAccumulator(
        in QuicAdaptiveRuntimeStage1PolicySnapshot configuredPolicy)
    {
        this.configuredPolicy = configuredPolicy;
    }

    public bool TryPublish(in QuicApplicationSendTurnEvidence evidence)
    {
        QuicAdaptiveRuntimeStage1ObservationValues values = CreateValues(
            evidence.Observation.QueuedApplicationWrites,
            evidence.Observation.OutboundBacklogBytes,
            evidence.Observation.DistinctQueuedStreams,
            evidence.Observation.OldestQueuedSendAgeMicros,
            evidence.Observation.QueueDelayEwmaMicros,
            evidence.Observation.ActorServiceTimeEwmaMicros,
            maximumPayloadBytes: null,
            eligibleWriteCount: null,
            eligibleWriteBytes: null,
            legalMaximumDatagrams: null,
            configuredMaximumDatagrams: null,
            evidence.Observation.BurstLimitHits,
            logicalWriteRemainingBytes: null,
            maximumChunkBytes: null,
            evidence.Observation.RetainedSendBuffers,
            evidence.Observation.RetainedSendBytes,
            evidence.Observation.BytesInFlight,
            evidence.Observation.CongestionWindowBytes,
            handshakeConfirmed: null,
            cancellationRequested: null,
            evidence.Observation.LifecycleFlags);
        lock (sync)
        {
            QuicAdaptiveRuntimeStage1AxisDecision decision = evidence.Decision;
            sendTurn.Publish(
                in decision,
                in values,
                QuicAdaptiveRuntimeStage1OutcomeScope.ActorTurn,
                selectedWriteCount: null,
                selectedPayloadBytes: null,
                appliedDatagramCap: null,
                emittedDatagrams: null,
                admittedFragments: null,
                continuationCount: null,
                completedOperations: 1);
        }

        return true;
    }

    public bool TryPublish(in QuicApplicationSendBatchEvidence evidence)
    {
        QuicAdaptiveRuntimeStage1ObservationValues values = CreateValues(
            evidence.Observation.QueuedApplicationWrites,
            evidence.Observation.OutboundBacklogBytes,
            evidence.Observation.DistinctQueuedStreams,
            evidence.Observation.OldestQueuedSendAgeMicros,
            evidence.Observation.QueueDelayEwmaMicros,
            evidence.Observation.ActorServiceTimeEwmaMicros,
            ToNullableUnsigned(evidence.Observation.MaximumPayloadBytes),
            ToNullableUnsigned(evidence.Observation.EligibleWriteCount),
            ToNullableUnsigned(evidence.Observation.EligibleWriteBytes),
            legalMaximumDatagrams: null,
            configuredMaximumDatagrams: null,
            burstLimitHits: null,
            logicalWriteRemainingBytes: null,
            maximumChunkBytes: null,
            evidence.Observation.RetainedSendBuffers,
            evidence.Observation.RetainedSendBytes,
            evidence.Observation.BytesInFlight,
            evidence.Observation.CongestionWindowBytes,
            handshakeConfirmed: null,
            cancellationRequested: null,
            evidence.Observation.LifecycleFlags);
        lock (sync)
        {
            QuicAdaptiveRuntimeStage1AxisDecision decision = evidence.Decision;
            sendBatch.Publish(
                in decision,
                in values,
                QuicAdaptiveRuntimeStage1OutcomeScope.Plan,
                ToNullableUnsigned(evidence.AppliedWriteCount),
                selectedPayloadBytes: null,
                appliedDatagramCap: null,
                emittedDatagrams: null,
                admittedFragments: null,
                continuationCount: null,
                completedOperations: 1);
            QuicApplicationSendBatchOperationEvidence operationEvidence =
                evidence.OperationEvidence;
            sendBatch.PublishBatchBehavior(in operationEvidence);
        }

        return true;
    }

    public bool TryPublish(in QuicQueuedSendBurstEvidence evidence)
    {
        QuicAdaptiveRuntimeStage1ObservationValues values = CreateValues(
            evidence.Observation.QueuedApplicationWrites,
            evidence.Observation.OutboundBacklogBytes,
            evidence.Observation.DistinctQueuedStreams,
            evidence.Observation.OldestQueuedSendAgeMicros,
            evidence.Observation.QueueDelayEwmaMicros,
            evidence.Observation.ActorServiceTimeEwmaMicros,
            maximumPayloadBytes: null,
            eligibleWriteCount: null,
            eligibleWriteBytes: null,
            ToNullableUnsigned(evidence.LegalMaximumDatagrams),
            ToNullableUnsigned(evidence.Observation.ConfiguredMaximumDatagrams),
            evidence.Observation.BurstLimitHits,
            logicalWriteRemainingBytes: null,
            maximumChunkBytes: null,
            evidence.Observation.RetainedSendBuffers,
            evidence.Observation.RetainedSendBytes,
            evidence.Observation.BytesInFlight,
            evidence.Observation.CongestionWindowBytes,
            evidence.Observation.HandshakeConfirmed,
            cancellationRequested: null,
            evidence.Observation.LifecycleFlags);
        lock (sync)
        {
            QuicAdaptiveRuntimeStage1AxisDecision decision = evidence.Decision;
            burstBudget.Publish(
                in decision,
                in values,
                QuicAdaptiveRuntimeStage1OutcomeScope.ActorTurn,
                selectedWriteCount: null,
                selectedPayloadBytes: null,
                ToNullableUnsigned(evidence.AppliedMaximumDatagrams),
                ToNullableUnsigned(evidence.EmittedDatagrams),
                admittedFragments: null,
                continuationCount: null,
                completedOperations: 1);
        }

        return true;
    }

    public bool TryPublish(in QuicOversizedWriteAdmissionEvidence evidence)
    {
        bool cancellationRequested =
            evidence.Outcome == QuicOversizedWriteOutcome.Canceled;
        QuicAdaptiveRuntimeStage1ObservationValues values = CreateValues(
            evidence.Observation.QueuedApplicationWrites,
            outboundBacklogBytes: null,
            evidence.Observation.DistinctObservedStreams,
            oldestQueuedSendAgeMicros: null,
            evidence.Observation.QueueDelayEwmaMicros,
            evidence.Observation.ActorServiceTimeEwmaMicros,
            ToNullableUnsigned(evidence.Observation.MaximumApplicationPayloadBytes),
            eligibleWriteCount: null,
            eligibleWriteBytes: null,
            legalMaximumDatagrams: null,
            configuredMaximumDatagrams: null,
            burstLimitHits: null,
            ToNullableUnsigned(evidence.Observation.LogicalRemainingBytes),
            ToNullableUnsigned(evidence.Observation.MaximumFragmentBytes),
            evidence.Observation.RetainedSendBuffers,
            evidence.Observation.RetainedSendBytes,
            evidence.Observation.BytesInFlight,
            evidence.Observation.CongestionWindowBytes,
            handshakeConfirmed: null,
            cancellationRequested,
            evidence.Observation.LifecycleFlags);
        lock (sync)
        {
            QuicAdaptiveRuntimeStage1AxisDecision decision = evidence.Decision;
            oversizedWrite.Publish(
                in decision,
                in values,
                QuicAdaptiveRuntimeStage1OutcomeScope.Operation,
                selectedWriteCount: null,
                selectedPayloadBytes: null,
                appliedDatagramCap: null,
                emittedDatagrams: null,
                ToNullableUnsigned(evidence.CommittedFragments),
                ToNullableUnsigned(evidence.ContinuationPosts),
                completedOperations: 1);
        }

        return true;
    }

    internal QuicAdaptiveRuntimeStage1EpochEvidence CaptureEpoch(
        ulong epochIndex,
        ulong epochStartOffsetMicros,
        ulong epochDurationMicros)
    {
        if (epochIndex == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(epochIndex));
        }

        if (epochDurationMicros == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(epochDurationMicros));
        }

        lock (sync)
        {
            if (epochIndex <= lastEpochIndex)
            {
                throw new InvalidOperationException(
                    "Stage 1 evidence epoch indexes must increase monotonically.");
            }

            QuicAdaptiveRuntimeStage1AxisDecision configuredSendTurn =
                configuredPolicy.ApplicationSendTurnPlanning;
            QuicAdaptiveRuntimeStage1AxisDecision configuredSendBatch =
                configuredPolicy.ApplicationSendBatchFormation;
            QuicAdaptiveRuntimeStage1AxisDecision configuredBurstBudget =
                configuredPolicy.QueuedSendBurstBudget;
            QuicAdaptiveRuntimeStage1AxisDecision configuredOversizedWrite =
                configuredPolicy.OversizedWriteAdmissionQuantum;
            QuicAdaptiveRuntimeStage1EpochAxisRecord sendTurnRecord =
                sendTurn.Capture(
                    in configuredSendTurn,
                    epochIndex,
                    QuicAdaptiveRuntimeStage1OutcomeScope.ActorTurn);
            QuicAdaptiveRuntimeStage1EpochAxisRecord sendBatchRecord =
                sendBatch.Capture(
                    in configuredSendBatch,
                    epochIndex,
                    QuicAdaptiveRuntimeStage1OutcomeScope.Plan);
            QuicAdaptiveRuntimeStage1EpochAxisRecord burstBudgetRecord =
                burstBudget.Capture(
                    in configuredBurstBudget,
                    epochIndex,
                    QuicAdaptiveRuntimeStage1OutcomeScope.ActorTurn);
            QuicAdaptiveRuntimeStage1EpochAxisRecord oversizedWriteRecord =
                oversizedWrite.Capture(
                    in configuredOversizedWrite,
                    epochIndex,
                    QuicAdaptiveRuntimeStage1OutcomeScope.Operation);
            QuicAdaptiveRuntimeStage1PolicySnapshot snapshot = new(
                sendTurnRecord.Decision,
                sendBatchRecord.Decision,
                burstBudgetRecord.Decision,
                oversizedWriteRecord.Decision);

            sendTurn = default;
            sendBatch = default;
            burstBudget = default;
            oversizedWrite = default;
            lastEpochIndex = epochIndex;

            return new QuicAdaptiveRuntimeStage1EpochEvidence(
                epochIndex,
                epochStartOffsetMicros,
                epochDurationMicros,
                snapshot,
                sendTurnRecord,
                sendBatchRecord,
                burstBudgetRecord,
                oversizedWriteRecord);
        }
    }

    private static QuicAdaptiveRuntimeStage1ObservationValues CreateValues(
        ulong? queuedApplicationWrites,
        ulong? outboundBacklogBytes,
        ulong? distinctQueuedSendStreams,
        ulong? oldestQueuedSendAgeMicros,
        ulong? queueDelayEwmaMicros,
        ulong? actorServiceTimeEwmaMicros,
        ulong? maximumPayloadBytes,
        ulong? eligibleWriteCount,
        ulong? eligibleWriteBytes,
        ulong? legalMaximumDatagrams,
        ulong? configuredMaximumDatagrams,
        ulong? burstLimitHits,
        ulong? logicalWriteRemainingBytes,
        ulong? maximumChunkBytes,
        ulong? retainedSendBuffers,
        ulong? retainedSendBytes,
        ulong? bytesInFlight,
        ulong? congestionWindowBytes,
        bool? handshakeConfirmed,
        bool? cancellationRequested,
        QuicAdaptiveRuntimeLifecycle lifecycleFlags)
        => new(
            queuedApplicationWrites,
            outboundBacklogBytes,
            distinctQueuedSendStreams,
            oldestQueuedSendAgeMicros,
            queueDelayEwmaMicros,
            actorServiceTimeEwmaMicros,
            maximumPayloadBytes,
            eligibleWriteCount,
            eligibleWriteBytes,
            legalMaximumDatagrams,
            configuredMaximumDatagrams,
            burstLimitHits,
            logicalWriteRemainingBytes,
            maximumChunkBytes,
            retainedSendBuffers,
            retainedSendBytes,
            bytesInFlight,
            congestionWindowBytes,
            handshakeConfirmed,
            cancellationRequested,
            (lifecycleFlags & QuicAdaptiveRuntimeLifecycle.Disposed) != 0,
            (lifecycleFlags & QuicAdaptiveRuntimeLifecycle.Terminal) != 0);

    private static ulong? ToNullableUnsigned(int value)
        => value < 0 ? null : (ulong)value;

    private struct AxisState
    {
        private QuicAdaptiveRuntimeStage1AxisDecision decision;
        private QuicAdaptiveRuntimeStage1ObservationValues observationValues;
        private QuicAdaptiveRuntimeStage1OutcomeScope scope;
        private ulong? selectedWriteCount;
        private ulong? selectedPayloadBytes;
        private ulong? appliedDatagramCap;
        private ulong? emittedDatagrams;
        private ulong? admittedFragments;
        private ulong? continuationCount;
        private ulong completedOperations;
        private ulong eventCount;
        private QuicApplicationSendBatchBehaviorEpochCounts
            batchBehaviorCounts;

        internal void Publish(
            in QuicAdaptiveRuntimeStage1AxisDecision publishedDecision,
            in QuicAdaptiveRuntimeStage1ObservationValues publishedValues,
            QuicAdaptiveRuntimeStage1OutcomeScope publishedScope,
            ulong? selectedWriteCount,
            ulong? selectedPayloadBytes,
            ulong? appliedDatagramCap,
            ulong? emittedDatagrams,
            ulong? admittedFragments,
            ulong? continuationCount,
            ulong completedOperations)
        {
            decision = publishedDecision;
            observationValues = publishedValues;
            scope = publishedScope;
            this.selectedWriteCount = Add(this.selectedWriteCount, selectedWriteCount);
            this.selectedPayloadBytes = Add(this.selectedPayloadBytes, selectedPayloadBytes);
            this.appliedDatagramCap = appliedDatagramCap ?? this.appliedDatagramCap;
            this.emittedDatagrams = Add(this.emittedDatagrams, emittedDatagrams);
            this.admittedFragments = Add(this.admittedFragments, admittedFragments);
            this.continuationCount = Add(this.continuationCount, continuationCount);
            this.completedOperations = SaturatingAdd(
                this.completedOperations,
                completedOperations);
            eventCount = SaturatingAdd(eventCount, 1);
        }

        internal void PublishBatchBehavior(
            in QuicApplicationSendBatchOperationEvidence operation)
        {
            ulong legalPrefixCount =
                batchBehaviorCounts.LegalEligiblePrefixOperationCount;
            ulong legalPrefixAppliedBytes =
                batchBehaviorCounts.LegalEligiblePrefixAppliedBytes;
            ulong singleEligibleCount =
                batchBehaviorCounts.SingleEligiblePrefixOperationCount;
            ulong singleEligibleAppliedBytes =
                batchBehaviorCounts.SingleEligiblePrefixAppliedBytes;
            ulong inactiveCount =
                batchBehaviorCounts.StructurallyInactiveOperationCount;
            ulong clampedCount =
                batchBehaviorCounts.ClampedOperationCount;
            ulong unclassifiableCount =
                batchBehaviorCounts.UnclassifiableOperationCount;

            switch (operation.MechanismEvent)
            {
                case QuicApplicationSendBatchMechanismEvent.LegalEligiblePrefixUsed:
                    legalPrefixCount = SaturatingAdd(legalPrefixCount, 1);
                    legalPrefixAppliedBytes = SaturatingAdd(
                        legalPrefixAppliedBytes,
                        operation.AppliedWriteBytes);
                    break;
                case QuicApplicationSendBatchMechanismEvent.SingleEligiblePrefixUsed:
                    singleEligibleCount = SaturatingAdd(singleEligibleCount, 1);
                    singleEligibleAppliedBytes = SaturatingAdd(
                        singleEligibleAppliedBytes,
                        operation.AppliedWriteBytes);
                    break;
                case QuicApplicationSendBatchMechanismEvent.Unclassifiable:
                    unclassifiableCount =
                        SaturatingAdd(unclassifiableCount, 1);
                    break;
                case QuicApplicationSendBatchMechanismEvent.NoPacketPlan:
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(operation));
            }

            if (operation.EligibilityReason
                == QuicAdaptiveRuntimeOperationEligibilityReason.StructurallyInactive)
            {
                inactiveCount = SaturatingAdd(inactiveCount, 1);
            }

            if (operation.EligibilityResult
                == QuicAdaptiveRuntimeOperationEligibilityResult.Clamped)
            {
                clampedCount = SaturatingAdd(clampedCount, 1);
            }

            batchBehaviorCounts = new(
                legalPrefixCount,
                legalPrefixAppliedBytes,
                singleEligibleCount,
                singleEligibleAppliedBytes,
                inactiveCount,
                clampedCount,
                unclassifiableCount,
                SaturatingAdd(
                    batchBehaviorCounts.TotalLegalWriteBytes,
                    operation.LegalWriteBytes),
                SaturatingAdd(
                    batchBehaviorCounts.TotalAppliedWriteBytes,
                    operation.AppliedWriteBytes));
        }

        internal readonly QuicAdaptiveRuntimeStage1EpochAxisRecord Capture(
            in QuicAdaptiveRuntimeStage1AxisDecision configuredDecision,
            ulong epochIndex,
            QuicAdaptiveRuntimeStage1OutcomeScope missingScope)
        {
            bool hasEvent = eventCount != 0;
            QuicAdaptiveRuntimeStage1AxisDecision capturedDecision = hasEvent
                ? decision
                : QuicAdaptiveRuntimeStage1MissingDecision.Create(
                    in configuredDecision,
                    epochIndex);
            QuicAdaptiveRuntimeStage1EpochOutcomes outcomes = new(
                hasEvent ? scope : missingScope,
                selectedWriteCount,
                selectedPayloadBytes,
                appliedDatagramCap,
                emittedDatagrams,
                admittedFragments,
                continuationCount,
                completedOperations,
                batchBehaviorCounts);
            return new QuicAdaptiveRuntimeStage1EpochAxisRecord(
                capturedDecision,
                observationValues,
                outcomes,
                eventCount,
                hasEvent);
        }

        private static ulong? Add(ulong? left, ulong? right)
            => right.HasValue
                ? SaturatingAdd(left.GetValueOrDefault(), right.Value)
                : left;

        private static ulong SaturatingAdd(ulong left, ulong right)
            => ulong.MaxValue - left < right ? ulong.MaxValue : left + right;
    }
}

internal static class QuicAdaptiveRuntimeStage1MissingDecision
{
    private const ushort MissingSignalReasonCode = 4;

    internal static QuicAdaptiveRuntimeStage1AxisDecision Create(
        in QuicAdaptiveRuntimeStage1AxisDecision configuredDecision,
        ulong epochIndex)
    {
        QuicAdaptiveRuntimeStage1PolicyValue conservativeValue =
            configuredDecision.Axis switch
            {
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning =>
                    QuicAdaptiveRuntimeStage1PolicyValue.Conservative,
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation =>
                    QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
                QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget =>
                    QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
                QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum =>
                    QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment,
                _ => throw new ArgumentOutOfRangeException(nameof(configuredDecision)),
            };
        bool hasShadowRecommendation =
            configuredDecision.HasShadowRecommendation;
        QuicAdaptiveRuntimeStage1PolicyValue selectedValue =
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
        if (configuredDecision.HasForcedValue)
        {
            selectedValue = configuredDecision.ForcedValue;
        }
        else if (hasShadowRecommendation)
        {
            selectedValue = conservativeValue;
        }

        QuicAdaptiveRuntimeStage1PolicyValue appliedValue =
            configuredDecision.HasForcedValue
                ? configuredDecision.ForcedValue
                : QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
        QuicAdaptiveRuntimeStage1SelectionSource selectionSource =
            QuicAdaptiveRuntimeStage1SelectionSource.Fallback;
        if (configuredDecision.HasForcedValue)
        {
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.Forced;
        }
        else if (hasShadowRecommendation)
        {
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.ShadowRule;
        }

        return configuredDecision with
        {
            Validity =
                configuredDecision.Validity
                | QuicAdaptiveRuntimeStage1Validity.Missing,
            ShadowRecommendation = conservativeValue,
            SelectedValue = selectedValue,
            AppliedValue = appliedValue,
            SelectionSource = selectionSource,
            ReasonCode = MissingSignalReasonCode,
            SafetyOverrideReason =
                QuicAdaptiveRuntimeStage1SafetyOverrideReason.None,
            LatchState = QuicAdaptiveRuntimeStage1LatchState.Unlatched,
            FallbackState = QuicAdaptiveRuntimeStage1FallbackState.Eligible,
            DecisionSequence = epochIndex,
            LatchSequence = 0,
        };
    }
}

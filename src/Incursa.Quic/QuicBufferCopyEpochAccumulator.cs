// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicBufferCopyEpochSummary(
    QuicBufferCopyConfiguredPolicySnapshot PolicySnapshot,
    bool HasObservation,
    ulong FirstOperationSequence,
    ulong LastOperationSequence,
    ulong OperationCount,
    ulong ApplicationWriteRequestCount,
    ulong OversizedRawQueueCount,
    ulong FormattedStreamPayloadCount,
    ulong CombinedApplicationSendCount,
    ulong SentPacketPlaintextRetentionCount,
    ulong RetransmissionCloneCount,
    ulong ReceiveSegmentCount,
    ulong OutboundPacketProtectionCount,
    ulong CopyCount,
    ulong ReuseAndCopyCount,
    ulong FormatCount,
    ulong CombineCount,
    ulong RetainCount,
    ulong CloneCount,
    ulong ProtectCount,
    ulong MemoryConservativeOperationCount,
    ulong SafetyOverrideOperationCount,
    ulong FallbackOperationCount,
    ulong TotalLegalLogicalBytes,
    ulong TotalLogicalBytes,
    ulong TotalCopiedBytes,
    ulong MaximumCopiedBytes,
    ulong TotalLegalSourceSegments,
    ulong TotalAppliedSourceSegments,
    ulong TotalRequestedCapacityBytes,
    ulong TotalRetainedCapacityBytes,
    ulong MaximumRetainedCapacityBytes,
    ulong ExactCombinedPrefixOperationCount,
    ulong ExactCombinedPrefixAppliedBytes,
    ulong TwoSourceCapOperationCount,
    ulong TwoSourceCapAppliedBytes,
    ulong StructurallyInactiveCoalescingOperationCount,
    ulong ClampedCoalescingOperationCount,
    ulong UnclassifiableCoalescingOperationCount,
    QuicBufferCopyValidity Validity)
{
    internal const string CurrentEpochContractVersion =
        "quic-buffer-copy-epoch-v4";

    public string EpochContractVersion => CurrentEpochContractVersion;
}

internal sealed class QuicBufferCopyEpochAccumulator :
    IQuicBufferCopyEvidenceSink
{
    private readonly object gate = new();
    private readonly QuicBufferCopyConfiguredPolicySnapshot policySnapshot;
    private bool hasObservation;
    private ulong firstOperationSequence;
    private ulong lastOperationSequence;
    private ulong operationCount;
    private ulong applicationWriteRequestCount;
    private ulong oversizedRawQueueCount;
    private ulong formattedStreamPayloadCount;
    private ulong combinedApplicationSendCount;
    private ulong sentPacketPlaintextRetentionCount;
    private ulong retransmissionCloneCount;
    private ulong receiveSegmentCount;
    private ulong outboundPacketProtectionCount;
    private ulong copyCount;
    private ulong reuseAndCopyCount;
    private ulong formatCount;
    private ulong combineCount;
    private ulong retainCount;
    private ulong cloneCount;
    private ulong protectCount;
    private ulong memoryConservativeOperationCount;
    private ulong safetyOverrideOperationCount;
    private ulong fallbackOperationCount;
    private ulong totalLegalLogicalBytes;
    private ulong totalLogicalBytes;
    private ulong totalCopiedBytes;
    private ulong maximumCopiedBytes;
    private ulong totalLegalSourceSegments;
    private ulong totalAppliedSourceSegments;
    private ulong totalRequestedCapacityBytes;
    private ulong totalRetainedCapacityBytes;
    private ulong maximumRetainedCapacityBytes;
    private ulong exactCombinedPrefixOperationCount;
    private ulong exactCombinedPrefixAppliedBytes;
    private ulong twoSourceCapOperationCount;
    private ulong twoSourceCapAppliedBytes;
    private ulong structurallyInactiveCoalescingOperationCount;
    private ulong clampedCoalescingOperationCount;
    private ulong unclassifiableCoalescingOperationCount;
    private QuicBufferCopyValidity validity;

    internal QuicBufferCopyEpochAccumulator()
        : this(QuicBufferCopyPolicy.CreateConfiguredSnapshot(
            QuicBufferCopyObservationMode.Disabled,
            forcedValue: null))
    {
    }

    internal QuicBufferCopyEpochAccumulator(
        in QuicBufferCopyConfiguredPolicySnapshot policySnapshot)
    {
        this.policySnapshot = policySnapshot;
    }

    public bool TryPublish(in QuicBufferCopyObservation observation)
    {
        lock (gate)
        {
            if (!hasObservation)
            {
                hasObservation = true;
                firstOperationSequence = observation.OperationSequence;
            }

            lastOperationSequence = observation.OperationSequence;
            AddSaturating(ref operationCount, 1);
            AddPath(observation.Path);
            AddOperation(observation.Operation);
            if (observation.AppliedValue
                == QuicBufferCopyPolicyValue.MemoryConservative)
            {
                AddSaturating(
                    ref memoryConservativeOperationCount,
                    1);
            }
            if (observation.SafetyOverride
                != QuicBufferCopySafetyOverride.None)
            {
                AddSaturating(ref safetyOverrideOperationCount, 1);
            }
            if (observation.FallbackApplied)
            {
                AddSaturating(ref fallbackOperationCount, 1);
            }
            AddSaturating(
                ref totalLegalLogicalBytes,
                observation.LegalLogicalBytes);
            AddSaturating(ref totalLogicalBytes, observation.LogicalBytes);
            AddSaturating(ref totalCopiedBytes, observation.CopiedBytes);
            maximumCopiedBytes = Math.Max(
                maximumCopiedBytes,
                observation.CopiedBytes);
            AddSaturating(
                ref totalLegalSourceSegments,
                observation.LegalSourceSegmentCount);
            AddSaturating(
                ref totalAppliedSourceSegments,
                observation.SourceSegmentCount);
            AddSaturating(
                ref totalRequestedCapacityBytes,
                observation.RequestedCapacityBytes);
            AddSaturating(
                ref totalRetainedCapacityBytes,
                observation.RetainedCapacityBytes);
            maximumRetainedCapacityBytes = Math.Max(
                maximumRetainedCapacityBytes,
                observation.RetainedCapacityBytes);
            QuicBufferCopyCoalescingOperationEvidence
                coalescingEvidence = observation.CoalescingEvidence;
            AddCoalescingEvidence(in coalescingEvidence);
            validity |= observation.Validity;
        }

        return true;
    }

    internal QuicBufferCopyEpochSummary CaptureAndReset()
    {
        lock (gate)
        {
            QuicBufferCopyEpochSummary summary = new(
                policySnapshot,
                hasObservation,
                firstOperationSequence,
                lastOperationSequence,
                operationCount,
                applicationWriteRequestCount,
                oversizedRawQueueCount,
                formattedStreamPayloadCount,
                combinedApplicationSendCount,
                sentPacketPlaintextRetentionCount,
                retransmissionCloneCount,
                receiveSegmentCount,
                outboundPacketProtectionCount,
                copyCount,
                reuseAndCopyCount,
                formatCount,
                combineCount,
                retainCount,
                cloneCount,
                protectCount,
                memoryConservativeOperationCount,
                safetyOverrideOperationCount,
                fallbackOperationCount,
                totalLegalLogicalBytes,
                totalLogicalBytes,
                totalCopiedBytes,
                maximumCopiedBytes,
                totalLegalSourceSegments,
                totalAppliedSourceSegments,
                totalRequestedCapacityBytes,
                totalRetainedCapacityBytes,
                maximumRetainedCapacityBytes,
                exactCombinedPrefixOperationCount,
                exactCombinedPrefixAppliedBytes,
                twoSourceCapOperationCount,
                twoSourceCapAppliedBytes,
                structurallyInactiveCoalescingOperationCount,
                clampedCoalescingOperationCount,
                unclassifiableCoalescingOperationCount,
                validity);
            Reset();
            return summary;
        }
    }

    private void AddPath(QuicBufferCopyPath path)
    {
        switch (path)
        {
            case QuicBufferCopyPath.ApplicationWriteRequest:
                AddSaturating(ref applicationWriteRequestCount, 1);
                break;
            case QuicBufferCopyPath.OversizedRawQueue:
                AddSaturating(ref oversizedRawQueueCount, 1);
                break;
            case QuicBufferCopyPath.FormattedStreamPayload:
                AddSaturating(ref formattedStreamPayloadCount, 1);
                break;
            case QuicBufferCopyPath.CombinedApplicationSend:
                AddSaturating(ref combinedApplicationSendCount, 1);
                break;
            case QuicBufferCopyPath.SentPacketPlaintextRetention:
                AddSaturating(
                    ref sentPacketPlaintextRetentionCount,
                    1);
                break;
            case QuicBufferCopyPath.RetransmissionClone:
                AddSaturating(ref retransmissionCloneCount, 1);
                break;
            case QuicBufferCopyPath.ReceiveSegment:
                AddSaturating(ref receiveSegmentCount, 1);
                break;
            case QuicBufferCopyPath.OutboundPacketProtection:
                AddSaturating(ref outboundPacketProtectionCount, 1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(path));
        }
    }

    private void AddOperation(QuicBufferCopyOperation operation)
    {
        switch (operation)
        {
            case QuicBufferCopyOperation.Copy:
                AddSaturating(ref copyCount, 1);
                break;
            case QuicBufferCopyOperation.ReuseAndCopy:
                AddSaturating(ref reuseAndCopyCount, 1);
                break;
            case QuicBufferCopyOperation.Format:
                AddSaturating(ref formatCount, 1);
                break;
            case QuicBufferCopyOperation.Combine:
                AddSaturating(ref combineCount, 1);
                break;
            case QuicBufferCopyOperation.Retain:
                AddSaturating(ref retainCount, 1);
                break;
            case QuicBufferCopyOperation.Clone:
                AddSaturating(ref cloneCount, 1);
                break;
            case QuicBufferCopyOperation.Protect:
                AddSaturating(ref protectCount, 1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }

    private void AddCoalescingEvidence(
        in QuicBufferCopyCoalescingOperationEvidence evidence)
    {
        if (evidence.OperationSequence == 0)
        {
            return;
        }

        switch (evidence.MechanismEvent)
        {
            case QuicBufferCopyCoalescingMechanismEvent
                    .ExactCombinedPrefixRetained:
                AddSaturating(
                    ref exactCombinedPrefixOperationCount,
                    1);
                AddSaturating(
                    ref exactCombinedPrefixAppliedBytes,
                    evidence.AppliedBytes);
                break;
            case QuicBufferCopyCoalescingMechanismEvent
                    .LowerTwoSourceSegmentCapApplied:
                AddSaturating(ref twoSourceCapOperationCount, 1);
                AddSaturating(
                    ref twoSourceCapAppliedBytes,
                    evidence.AppliedBytes);
                break;
            case QuicBufferCopyCoalescingMechanismEvent.Unclassifiable:
                AddSaturating(
                    ref unclassifiableCoalescingOperationCount,
                    1);
                break;
            case QuicBufferCopyCoalescingMechanismEvent
                    .NoCombinedOwnerRented:
            case QuicBufferCopyCoalescingMechanismEvent.NotAxisMechanism:
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(evidence));
        }

        if (evidence.EligibilityReason
            == QuicAdaptiveRuntimeOperationEligibilityReason.StructurallyInactive)
        {
            AddSaturating(
                ref structurallyInactiveCoalescingOperationCount,
                1);
        }

        if (evidence.EligibilityResult
            == QuicAdaptiveRuntimeOperationEligibilityResult.Clamped)
        {
            AddSaturating(ref clampedCoalescingOperationCount, 1);
        }
    }

    private void AddSaturating(ref ulong target, ulong value)
    {
        if (ulong.MaxValue - target < value)
        {
            target = ulong.MaxValue;
            validity |= QuicBufferCopyValidity.ArithmeticSaturated;
            return;
        }

        target += value;
    }

    private void Reset()
    {
        hasObservation = false;
        firstOperationSequence = 0;
        lastOperationSequence = 0;
        operationCount = 0;
        applicationWriteRequestCount = 0;
        oversizedRawQueueCount = 0;
        formattedStreamPayloadCount = 0;
        combinedApplicationSendCount = 0;
        sentPacketPlaintextRetentionCount = 0;
        retransmissionCloneCount = 0;
        receiveSegmentCount = 0;
        outboundPacketProtectionCount = 0;
        copyCount = 0;
        reuseAndCopyCount = 0;
        formatCount = 0;
        combineCount = 0;
        retainCount = 0;
        cloneCount = 0;
        protectCount = 0;
        memoryConservativeOperationCount = 0;
        safetyOverrideOperationCount = 0;
        fallbackOperationCount = 0;
        totalLegalLogicalBytes = 0;
        totalLogicalBytes = 0;
        totalCopiedBytes = 0;
        maximumCopiedBytes = 0;
        totalLegalSourceSegments = 0;
        totalAppliedSourceSegments = 0;
        totalRequestedCapacityBytes = 0;
        totalRetainedCapacityBytes = 0;
        maximumRetainedCapacityBytes = 0;
        exactCombinedPrefixOperationCount = 0;
        exactCombinedPrefixAppliedBytes = 0;
        twoSourceCapOperationCount = 0;
        twoSourceCapAppliedBytes = 0;
        structurallyInactiveCoalescingOperationCount = 0;
        clampedCoalescingOperationCount = 0;
        unclassifiableCoalescingOperationCount = 0;
        validity = QuicBufferCopyValidity.None;
    }
}

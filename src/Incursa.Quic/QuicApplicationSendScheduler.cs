// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicApplicationSendPlanKind
{
    None,
    SingleWrite,
    Fragment,
    Batch,
}

internal readonly record struct QuicApplicationSendPlan(
    QuicApplicationSendPlanKind Kind,
    int SelectedWriteCount,
    int FragmentDataLength,
    bool HasMoreQueuedData,
    QuicSendPolicyBlockedReason BlockedReason,
    ulong FirstStreamId,
    QuicApplicationSendBatchPolicyMode BatchPolicyMode,
    int EligibleWriteCount,
    int EligibleWriteBytes,
    int SelectedWriteBytes)
{
    internal static QuicApplicationSendPlan None(
        QuicSendPolicyBlockedReason blockedReason,
        QuicApplicationSendBatchPolicyMode batchPolicyMode =
            QuicApplicationSendBatchPolicyMode.LegacyCurrent)
        => new(
            QuicApplicationSendPlanKind.None,
            SelectedWriteCount: 0,
            FragmentDataLength: 0,
            HasMoreQueuedData: false,
            blockedReason,
            FirstStreamId: 0,
            batchPolicyMode,
            EligibleWriteCount: 0,
            EligibleWriteBytes: 0,
            SelectedWriteBytes: 0);
}

internal static class QuicApplicationSendScheduler
{
    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        PendingApplicationSendRequest queuedWrite,
        QuicQueuedApplicationSendBudget budget,
        out Exception? exception)
    {
        QuicStreamFrame firstStreamFrame;
        return SelectQueuedApplicationSendPlan(
            queuedWrite,
            budget,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            out firstStreamFrame,
            out exception);
    }

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        PendingApplicationSendRequest queuedWrite,
        QuicQueuedApplicationSendBudget budget,
        QuicApplicationSendBatchPolicyMode batchPolicyMode,
        out Exception? exception)
    {
        QuicStreamFrame firstStreamFrame;
        return SelectQueuedApplicationSendPlan(
            queuedWrite,
            budget,
            batchPolicyMode,
            out firstStreamFrame,
            out exception);
    }

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        PendingApplicationSendRequest queuedWrite,
        QuicQueuedApplicationSendBudget budget,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
        => SelectQueuedApplicationSendPlan(
            queuedWrite,
            budget,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            out firstStreamFrame,
            out exception);

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        PendingApplicationSendRequest queuedWrite,
        QuicQueuedApplicationSendBudget budget,
        QuicApplicationSendBatchPolicyMode batchPolicyMode,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
        => SelectQueuedApplicationSendPlanCore(
            queuedWrite,
            sortedQueuedWrites: default,
            queuedWriteCount: 1,
            budget,
            batchPolicyMode,
            out firstStreamFrame,
            out exception);

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
        QuicQueuedApplicationSendBudget budget,
        out Exception? exception)
    {
        QuicStreamFrame firstStreamFrame;
        return SelectQueuedApplicationSendPlan(
            sortedQueuedWrites,
            budget,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            out firstStreamFrame,
            out exception);
    }

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
        QuicQueuedApplicationSendBudget budget,
        QuicApplicationSendBatchPolicyMode batchPolicyMode,
        out Exception? exception)
    {
        QuicStreamFrame firstStreamFrame;
        return SelectQueuedApplicationSendPlan(
            sortedQueuedWrites,
            budget,
            batchPolicyMode,
            out firstStreamFrame,
            out exception);
    }

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
        QuicQueuedApplicationSendBudget budget,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
        => SelectQueuedApplicationSendPlan(
            sortedQueuedWrites,
            budget,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            out firstStreamFrame,
            out exception);

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
        QuicQueuedApplicationSendBudget budget,
        QuicApplicationSendBatchPolicyMode batchPolicyMode,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
    {
        QuicApplicationSendBatchPolicy.ValidateMode(batchPolicyMode);
        if (sortedQueuedWrites.IsEmpty)
        {
            exception = null;
            firstStreamFrame = default;
            return QuicApplicationSendPlan.None(
                QuicSendPolicyBlockedReason.NoQueuedApplicationData,
                batchPolicyMode);
        }

        return SelectQueuedApplicationSendPlanCore(
            sortedQueuedWrites[0],
            sortedQueuedWrites,
            sortedQueuedWrites.Length,
            budget,
            batchPolicyMode,
            out firstStreamFrame,
            out exception);
    }

    private static QuicApplicationSendPlan SelectQueuedApplicationSendPlanCore(
        PendingApplicationSendRequest firstQueuedWrite,
        ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
        int queuedWriteCount,
        QuicQueuedApplicationSendBudget budget,
        QuicApplicationSendBatchPolicyMode batchPolicyMode,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
    {
        exception = null;
        firstStreamFrame = default;
        QuicApplicationSendBatchPolicy.ValidateMode(batchPolicyMode);

        if (queuedWriteCount <= 0)
        {
            return QuicApplicationSendPlan.None(
                QuicSendPolicyBlockedReason.NoQueuedApplicationData,
                batchPolicyMode);
        }

        if (!budget.CanSendQueuedApplicationData || budget.MaxDatagrams <= 0 || budget.MaxPayloadBytes <= 0)
        {
            return QuicApplicationSendPlan.None(budget.BlockedReason, batchPolicyMode);
        }

        if (!firstQueuedWrite.TryGetStreamFrame(out firstStreamFrame))
        {
            exception = new InvalidOperationException("Queued application stream payload is not a valid STREAM frame.");
            return QuicApplicationSendPlan.None(
                QuicSendPolicyBlockedReason.InvalidQueuedApplicationSend,
                batchPolicyMode);
        }

        if (!QuicStreamPayloadSizer.TryGetFragmentDataLength(
            firstStreamFrame,
            budget.MaxPayloadBytes,
            out int fragmentDataLength))
        {
            return QuicApplicationSendPlan.None(
                QuicSendPolicyBlockedReason.InvalidPayloadBudget,
                batchPolicyMode);
        }

        if (fragmentDataLength < firstStreamFrame.StreamDataLength)
        {
            return new QuicApplicationSendPlan(
                QuicApplicationSendPlanKind.Fragment,
                SelectedWriteCount: 1,
                fragmentDataLength,
                HasMoreQueuedData: true,
                QuicSendPolicyBlockedReason.None,
                firstStreamFrame.StreamId.Value,
                batchPolicyMode,
                EligibleWriteCount: 1,
                EligibleWriteBytes: firstQueuedWrite.StreamPayloadLength,
                SelectedWriteBytes: fragmentDataLength);
        }

        int eligibleWriteBytes;
        int eligibleWriteCount = queuedWriteCount == 1 || firstQueuedWrite.ContainsRawStreamData
            ? GetSingleEligibleWrite(firstQueuedWrite, out eligibleWriteBytes)
            : QuicApplicationSendQueue.SelectQueuedApplicationSendBatchCount(
                sortedQueuedWrites,
                budget.MaxPayloadBytes,
                out eligibleWriteBytes);
        int selectedWriteCount = QuicApplicationSendBatchPolicy.SelectWriteCount(
            batchPolicyMode,
            eligibleWriteCount);
        if (selectedWriteCount <= 0)
        {
            return QuicApplicationSendPlan.None(
                QuicSendPolicyBlockedReason.InvalidPayloadBudget,
                batchPolicyMode);
        }

        return new QuicApplicationSendPlan(
            selectedWriteCount == 1 ? QuicApplicationSendPlanKind.SingleWrite : QuicApplicationSendPlanKind.Batch,
            selectedWriteCount,
            fragmentDataLength,
            HasMoreQueuedData: selectedWriteCount < queuedWriteCount,
            QuicSendPolicyBlockedReason.None,
            firstStreamFrame.StreamId.Value,
            batchPolicyMode,
            eligibleWriteCount,
            eligibleWriteBytes,
            selectedWriteCount == eligibleWriteCount
                ? eligibleWriteBytes
                : firstQueuedWrite.StreamPayloadLength);
    }

    private static int GetSingleEligibleWrite(
        PendingApplicationSendRequest queuedWrite,
        out int eligibleWriteBytes)
    {
        eligibleWriteBytes = queuedWrite.StreamPayloadLength;
        return 1;
    }
}

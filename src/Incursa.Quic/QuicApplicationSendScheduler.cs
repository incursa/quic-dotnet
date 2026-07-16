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
    ulong FirstStreamId)
{
    internal static QuicApplicationSendPlan None(QuicSendPolicyBlockedReason blockedReason)
        => new(
            QuicApplicationSendPlanKind.None,
            SelectedWriteCount: 0,
            FragmentDataLength: 0,
            HasMoreQueuedData: false,
            blockedReason,
            FirstStreamId: 0);
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
            out firstStreamFrame,
            out exception);
    }

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        PendingApplicationSendRequest queuedWrite,
        QuicQueuedApplicationSendBudget budget,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
        => SelectQueuedApplicationSendPlanCore(
            queuedWrite,
            sortedQueuedWrites: default,
            queuedWriteCount: 1,
            budget,
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
            out firstStreamFrame,
            out exception);
    }

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
        QuicQueuedApplicationSendBudget budget,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
    {
        if (sortedQueuedWrites.IsEmpty)
        {
            exception = null;
            firstStreamFrame = default;
            return QuicApplicationSendPlan.None(QuicSendPolicyBlockedReason.NoQueuedApplicationData);
        }

        return SelectQueuedApplicationSendPlanCore(
            sortedQueuedWrites[0],
            sortedQueuedWrites,
            sortedQueuedWrites.Length,
            budget,
            out firstStreamFrame,
            out exception);
    }

    private static QuicApplicationSendPlan SelectQueuedApplicationSendPlanCore(
        PendingApplicationSendRequest firstQueuedWrite,
        ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
        int queuedWriteCount,
        QuicQueuedApplicationSendBudget budget,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
    {
        exception = null;
        firstStreamFrame = default;

        if (queuedWriteCount <= 0)
        {
            return QuicApplicationSendPlan.None(QuicSendPolicyBlockedReason.NoQueuedApplicationData);
        }

        if (!budget.CanSendQueuedApplicationData || budget.MaxDatagrams <= 0 || budget.MaxPayloadBytes <= 0)
        {
            return QuicApplicationSendPlan.None(budget.BlockedReason);
        }

        if (!QuicStreamParser.TryParseStreamFrame(
            firstQueuedWrite.StreamPayload.AsSpan(0, firstQueuedWrite.StreamPayloadLength),
            out firstStreamFrame))
        {
            exception = new InvalidOperationException("Queued application stream payload is not a valid STREAM frame.");
            return QuicApplicationSendPlan.None(QuicSendPolicyBlockedReason.InvalidQueuedApplicationSend);
        }

        if (!QuicStreamPayloadSizer.TryGetFragmentDataLength(
            firstStreamFrame,
            budget.MaxPayloadBytes,
            out int fragmentDataLength))
        {
            return QuicApplicationSendPlan.None(QuicSendPolicyBlockedReason.InvalidPayloadBudget);
        }

        if (fragmentDataLength < firstStreamFrame.StreamDataLength)
        {
            return new QuicApplicationSendPlan(
                QuicApplicationSendPlanKind.Fragment,
                SelectedWriteCount: 1,
                fragmentDataLength,
                HasMoreQueuedData: true,
                QuicSendPolicyBlockedReason.None,
                firstStreamFrame.StreamId.Value);
        }

        int selectedWriteCount = queuedWriteCount == 1
            ? 1
            : QuicApplicationSendQueue.SelectQueuedApplicationSendBatchCount(
                sortedQueuedWrites,
                budget.MaxPayloadBytes);
        if (selectedWriteCount <= 0)
        {
            return QuicApplicationSendPlan.None(QuicSendPolicyBlockedReason.InvalidPayloadBudget);
        }

        return new QuicApplicationSendPlan(
            selectedWriteCount == 1 ? QuicApplicationSendPlanKind.SingleWrite : QuicApplicationSendPlanKind.Batch,
            selectedWriteCount,
            fragmentDataLength,
            HasMoreQueuedData: selectedWriteCount < queuedWriteCount,
            QuicSendPolicyBlockedReason.None,
            firstStreamFrame.StreamId.Value);
    }
}

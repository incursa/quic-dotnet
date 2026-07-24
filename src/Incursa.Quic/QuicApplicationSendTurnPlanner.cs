// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicApplicationSendTurnContext(
    int InitialQueuedWriteCount,
    int RemainingQueuedWriteCount,
    int FlushedDatagramCount,
    QuicQueuedApplicationSendBudget Budget);

/// <summary>
/// Selects queued application data within runtime-enforced send budgets.
/// </summary>
/// <remarks>
/// Implementations are connection-local. They do not own payloads, mutate the authoritative queue,
/// or change congestion, anti-amplification, retransmission, flow-control, or recovery state.
/// </remarks>
internal interface IQuicApplicationSendTurnPlanner
{
    bool ShouldScheduleNext(in QuicApplicationSendTurnContext context);

    int SelectFirstQueuedWriteIndex(
        ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
        QuicQueuedApplicationSendBudget budget);
}

internal static class QuicApplicationSendTurnPlannerDispatch
{
    internal static bool ShouldScheduleNext(
        IQuicApplicationSendTurnPlanner? planner,
        in QuicApplicationSendTurnContext context)
        => planner is null || planner.ShouldScheduleNext(context);

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        IQuicApplicationSendTurnPlanner? planner,
        Span<PendingApplicationSendRequest> sortedQueuedWrites,
        QuicQueuedApplicationSendBudget budget,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
        => SelectQueuedApplicationSendPlan(
            planner,
            sortedQueuedWrites,
            budget,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            out firstStreamFrame,
            out exception);

    internal static QuicApplicationSendPlan SelectQueuedApplicationSendPlan(
        IQuicApplicationSendTurnPlanner? planner,
        Span<PendingApplicationSendRequest> sortedQueuedWrites,
        QuicQueuedApplicationSendBudget budget,
        QuicApplicationSendBatchPolicyMode batchPolicyMode,
        out QuicStreamFrame firstStreamFrame,
        out Exception? exception)
    {
        if (planner is not null && !sortedQueuedWrites.IsEmpty)
        {
            int selectedIndex = planner.SelectFirstQueuedWriteIndex(sortedQueuedWrites, budget);
            if ((uint)selectedIndex >= (uint)sortedQueuedWrites.Length)
            {
                firstStreamFrame = default;
                exception = new InvalidOperationException(
                    "The application-send turn planner selected a queued-write index outside the planning snapshot.");
                return QuicApplicationSendPlan.None(QuicSendPolicyBlockedReason.InvalidQueuedApplicationSend);
            }

            if (selectedIndex > 0)
            {
                PendingApplicationSendRequest selectedWrite = sortedQueuedWrites[selectedIndex];
                for (int index = 0; index < selectedIndex; index++)
                {
                    if (sortedQueuedWrites[index].StreamId == selectedWrite.StreamId)
                    {
                        firstStreamFrame = default;
                        exception = new InvalidOperationException(
                            "The application-send turn planner selected a later queued write before an earlier write for the same stream.");
                        return QuicApplicationSendPlan.None(QuicSendPolicyBlockedReason.InvalidQueuedApplicationSend);
                    }
                }

                sortedQueuedWrites[..selectedIndex].CopyTo(sortedQueuedWrites[1..]);
                sortedQueuedWrites[0] = selectedWrite;
            }
        }

        return QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            sortedQueuedWrites,
            budget,
            batchPolicyMode,
            out firstStreamFrame,
            out exception);
    }
}

/// <summary>
/// Explicit control implementation that preserves the current static scheduler.
/// </summary>
internal sealed class QuicCurrentApplicationSendTurnPlanner : IQuicApplicationSendTurnPlanner
{
    internal static QuicCurrentApplicationSendTurnPlanner Instance { get; } = new();

    private QuicCurrentApplicationSendTurnPlanner()
    {
    }

    bool IQuicApplicationSendTurnPlanner.ShouldScheduleNext(in QuicApplicationSendTurnContext context)
        => true;

    int IQuicApplicationSendTurnPlanner.SelectFirstQueuedWriteIndex(
        ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
        QuicQueuedApplicationSendBudget budget)
        => 0;
}

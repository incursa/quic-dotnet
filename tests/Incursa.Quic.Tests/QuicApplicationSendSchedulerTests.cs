// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;

namespace Incursa.Quic.Tests;

public sealed class QuicApplicationSendSchedulerTests
{
    [Fact]
    public void SelectQueuedApplicationSendPlanFragmentsRawStreamDataWithoutBatchingLaterWrites()
    {
        PendingApplicationSendRequest rawWrite = new(
            Sequence: 0,
            StreamId: 4,
            Priority: 0,
            StreamPayload: Enumerable.Range(0, 96).Select(static value => (byte)value).ToArray(),
            StreamPayloadLength: 96,
            ContainsRawStreamData: true,
            StreamOffset: 17,
            IsFinal: true);
        PendingApplicationSendRequest encodedWrite = CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 8);

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            [rawWrite, encodedWrite],
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maxPayloadBytes: 40),
            out QuicStreamFrame frame,
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Fragment, plan.Kind);
        Assert.Equal(1, plan.SelectedWriteCount);
        Assert.InRange(plan.FragmentDataLength, 1, 95);
        Assert.Equal(4UL, frame.StreamId.Value);
        Assert.Equal(17UL, frame.Offset);
        Assert.True(frame.IsFin);
        Assert.Equal(96, frame.StreamDataLength);
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_SelectsNoWorkWhenBudgetIsZero()
    {
        PendingApplicationSendRequest[] queuedWrites = [CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 16)];

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrites,
            QuicQueuedApplicationSendBudget.Blocked(QuicSendPolicyBlockedReason.CongestionLimited),
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.None, plan.Kind);
        Assert.Equal(0, plan.SelectedWriteCount);
        Assert.Equal(QuicSendPolicyBlockedReason.CongestionLimited, plan.BlockedReason);
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_SelectsPayloadBoundedBatch()
    {
        PendingApplicationSendRequest first = CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 8);
        PendingApplicationSendRequest second = CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 8);
        PendingApplicationSendRequest third = CreateQueuedWrite(sequence: 2, streamId: 12, dataLength: 8);
        PendingApplicationSendRequest[] queuedWrites = [first, second, third];
        int maximumPayloadBytes = first.StreamPayloadLength + second.StreamPayloadLength;

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrites,
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maximumPayloadBytes),
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Batch, plan.Kind);
        Assert.Equal(2, plan.SelectedWriteCount);
        Assert.True(plan.HasMoreQueuedData);
        Assert.Equal([4UL, 8UL], queuedWrites[..plan.SelectedWriteCount].Select(write => write.StreamId));
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_FragmentsOversizedQueuedWriteWithoutDrainingIt()
    {
        PendingApplicationSendRequest queuedWrite = CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 96);

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            [queuedWrite],
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maxPayloadBytes: 40),
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Fragment, plan.Kind);
        Assert.Equal(1, plan.SelectedWriteCount);
        Assert.InRange(plan.FragmentDataLength, 1, 95);
        Assert.True(plan.HasMoreQueuedData);
        Assert.Equal(4UL, plan.FirstStreamId);
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_ReturnsParsedFirstStreamFrameView()
    {
        PendingApplicationSendRequest queuedWrite = CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 96);

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrite,
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maxPayloadBytes: 40),
            out QuicStreamFrame firstStreamFrame,
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Fragment, plan.Kind);
        Assert.Equal(4UL, firstStreamFrame.StreamId.Value);
        Assert.Equal(96, firstStreamFrame.StreamDataLength);
        Assert.Equal(firstStreamFrame.StreamId.Value, plan.FirstStreamId);
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_PreservesPriorityAndSequenceOrderProvidedByQueue()
    {
        QuicApplicationSendQueue queue = new();
        byte[] lowPriorityPayload = CreateQueuedWritePayload(streamId: 4, dataLength: 4);
        byte[] firstHighPriorityPayload = CreateQueuedWritePayload(streamId: 8, dataLength: 4);
        byte[] secondHighPriorityPayload = CreateQueuedWritePayload(streamId: 12, dataLength: 4);
        queue.Enqueue(4, priority: 0, lowPriorityPayload, lowPriorityPayload.Length);
        queue.Enqueue(8, priority: 5, firstHighPriorityPayload, firstHighPriorityPayload.Length);
        queue.Enqueue(12, priority: 5, secondHighPriorityPayload, secondHighPriorityPayload.Length);

        PendingApplicationSendRequest[] sortedQueuedWrites = queue.RentSortedQueuedWrites(out int queuedWriteCount);
        try
        {
            QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                sortedQueuedWrites.AsSpan(0, queuedWriteCount),
                QuicQueuedApplicationSendBudget.AllowSingleDatagram(maxPayloadBytes: 64),
                out Exception? exception);

            Assert.Null(exception);
            Assert.Equal(QuicApplicationSendPlanKind.Batch, plan.Kind);
            Assert.Equal(3, plan.SelectedWriteCount);
            Assert.Equal([8UL, 12UL, 4UL], sortedQueuedWrites.AsSpan(0, plan.SelectedWriteCount).ToArray().Select(write => write.StreamId));
            Assert.Equal([5, 5, 0], sortedQueuedWrites.AsSpan(0, plan.SelectedWriteCount).ToArray().Select(write => write.Priority));
            Assert.Equal([1L, 2L, 0L], sortedQueuedWrites.AsSpan(0, plan.SelectedWriteCount).ToArray().Select(write => write.Sequence));
        }
        finally
        {
            QuicApplicationSendQueue.ReturnRentedQueuedWrites(sortedQueuedWrites);
        }
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_ReportsMoreWorkWhenQueueIsNotDrained()
    {
        PendingApplicationSendRequest first = CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 4);
        PendingApplicationSendRequest second = CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 4);
        PendingApplicationSendRequest third = CreateQueuedWrite(sequence: 2, streamId: 12, dataLength: 4);
        PendingApplicationSendRequest[] queuedWrites = [first, second, third];
        int maximumPayloadBytes = first.StreamPayloadLength + second.StreamPayloadLength;

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrites,
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maximumPayloadBytes),
            out Exception? exception);

        Assert.Null(exception);
        Assert.True(plan.HasMoreQueuedData);
        Assert.Equal(2, plan.SelectedWriteCount);
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_SelectsStandaloneFinAsASingleWrite()
    {
        PendingApplicationSendRequest queuedWrite = CreateQueuedWrite(
            sequence: 0,
            streamId: 4,
            dataLength: 0,
            fin: true);

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrite,
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maxPayloadBytes: 32),
            out QuicStreamFrame frame,
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.SingleWrite, plan.Kind);
        Assert.Equal(1, plan.SelectedWriteCount);
        Assert.Equal(0, plan.FragmentDataLength);
        Assert.False(plan.HasMoreQueuedData);
        Assert.Equal(0, frame.StreamDataLength);
        Assert.True(frame.IsFin);
    }

    [Fact]
    public void SelectQueuedApplicationSendPlan_DefersStandaloneFinWhenBudgetCannotFitItsHeader()
    {
        PendingApplicationSendRequest queuedWrite = CreateQueuedWrite(
            sequence: 0,
            streamId: 400,
            dataLength: 0,
            fin: true);

        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrite,
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(maxPayloadBytes: 1),
            out QuicStreamFrame frame,
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.None, plan.Kind);
        Assert.Equal(QuicSendPolicyBlockedReason.InvalidPayloadBudget, plan.BlockedReason);
        Assert.Equal(0, frame.StreamDataLength);
        Assert.True(frame.IsFin);
    }

    [Fact]
    public void CurrentTurnPlannerMatchesStaticScheduler()
    {
        PendingApplicationSendRequest[] directWrites =
        [
            CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 8),
            CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 8),
        ];
        PendingApplicationSendRequest[] plannedWrites = [.. directWrites];
        QuicQueuedApplicationSendBudget budget = QuicQueuedApplicationSendBudget.AllowSingleDatagram(
            directWrites.Sum(static write => write.StreamPayloadLength));
        QuicApplicationSendTurnContext context = new(
            InitialQueuedWriteCount: directWrites.Length,
            RemainingQueuedWriteCount: directWrites.Length,
            FlushedDatagramCount: 0,
            budget);

        QuicApplicationSendPlan directPlan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            directWrites,
            budget,
            out QuicStreamFrame directFrame,
            out Exception? directException);
        IQuicApplicationSendTurnPlanner planner = QuicCurrentApplicationSendTurnPlanner.Instance;
        QuicApplicationSendPlan plannedPlan = QuicApplicationSendTurnPlannerDispatch.SelectQueuedApplicationSendPlan(
            planner,
            plannedWrites,
            budget,
            out QuicStreamFrame plannedFrame,
            out Exception? plannedException);

        Assert.Null(directException);
        Assert.Null(plannedException);
        Assert.Equal(directPlan, plannedPlan);
        Assert.Equal(directFrame.StreamId, plannedFrame.StreamId);
        Assert.Equal(directFrame.Offset, plannedFrame.Offset);
        Assert.Equal(directFrame.StreamDataLength, plannedFrame.StreamDataLength);
        Assert.Equal(directFrame.IsFin, plannedFrame.IsFin);
        Assert.True(QuicApplicationSendTurnPlannerDispatch.ShouldScheduleNext(planner, context));
    }

    [Fact]
    public void AlternateTurnPlannerCanReorderOnlyItsQueueSnapshot()
    {
        PendingApplicationSendRequest first = CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 8);
        PendingApplicationSendRequest second = CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 8);
        PendingApplicationSendRequest[] authoritativeOrder = [first, second];
        PendingApplicationSendRequest[] planningSnapshot = [.. authoritativeOrder];
        QuicQueuedApplicationSendBudget budget = QuicQueuedApplicationSendBudget.AllowSingleDatagram(
            first.StreamPayloadLength + second.StreamPayloadLength);
        QuicApplicationSendTurnContext context = new(2, 2, 0, budget);
        RecordingTurnPlanner planner = new(selectedWriteIndex: 1);

        QuicApplicationSendPlan plan = QuicApplicationSendTurnPlannerDispatch.SelectQueuedApplicationSendPlan(
            planner,
            planningSnapshot,
            budget,
            out QuicStreamFrame firstFrame,
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Batch, plan.Kind);
        Assert.Equal(8UL, firstFrame.StreamId.Value);
        Assert.Equal([8UL, 4UL], planningSnapshot.Select(static write => write.StreamId));
        Assert.Equal([4UL, 8UL], authoritativeOrder.Select(static write => write.StreamId));
        Assert.Equal(1, planner.SelectionCount);
    }

    [Fact]
    public void AlternateTurnPlannerSelectionStillUsesRuntimeFragmentationRules()
    {
        PendingApplicationSendRequest first = CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 8);
        PendingApplicationSendRequest oversized = CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 64);
        PendingApplicationSendRequest[] authoritativeOrder = [first, oversized];
        PendingApplicationSendRequest[] planningSnapshot = [.. authoritativeOrder];
        QuicQueuedApplicationSendBudget budget = QuicQueuedApplicationSendBudget.AllowSingleDatagram(
            first.StreamPayloadLength + 12);
        QuicApplicationSendTurnContext context = new(2, 2, 0, budget);
        RecordingTurnPlanner planner = new(selectedWriteIndex: 1);

        QuicApplicationSendPlan plan = QuicApplicationSendTurnPlannerDispatch.SelectQueuedApplicationSendPlan(
            planner,
            planningSnapshot,
            budget,
            out QuicStreamFrame firstFrame,
            out Exception? exception);

        Assert.Null(exception);
        Assert.Equal(QuicApplicationSendPlanKind.Fragment, plan.Kind);
        Assert.Equal(1, plan.SelectedWriteCount);
        Assert.Equal(8UL, firstFrame.StreamId.Value);
        Assert.InRange(plan.FragmentDataLength, 1, firstFrame.StreamDataLength - 1);
        Assert.Equal([4UL, 8UL], authoritativeOrder.Select(static write => write.StreamId));
    }

    [Fact]
    public void AlternateTurnPlannerRejectsSelectionOutsideTheQueueSnapshot()
    {
        PendingApplicationSendRequest[] planningSnapshot =
        [
            CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 8),
        ];
        QuicQueuedApplicationSendBudget budget = QuicQueuedApplicationSendBudget.AllowSingleDatagram(64);
        QuicApplicationSendTurnContext context = new(1, 1, 0, budget);
        RecordingTurnPlanner planner = new(selectedWriteIndex: 1);

        QuicApplicationSendPlan plan = QuicApplicationSendTurnPlannerDispatch.SelectQueuedApplicationSendPlan(
            planner,
            planningSnapshot,
            budget,
            out _,
            out Exception? exception);

        Assert.Equal(QuicApplicationSendPlanKind.None, plan.Kind);
        Assert.Equal(QuicSendPolicyBlockedReason.InvalidQueuedApplicationSend, plan.BlockedReason);
        Assert.IsType<InvalidOperationException>(exception);
    }

    [Fact]
    public void AlternateTurnPlannerCannotOvertakeAnEarlierWriteOnTheSameStream()
    {
        PendingApplicationSendRequest[] planningSnapshot =
        [
            CreateQueuedWrite(sequence: 0, streamId: 4, dataLength: 8),
            CreateQueuedWrite(sequence: 1, streamId: 8, dataLength: 8),
            CreateQueuedWrite(sequence: 2, streamId: 4, dataLength: 8),
        ];
        PendingApplicationSendRequest[] originalOrder = [.. planningSnapshot];
        QuicQueuedApplicationSendBudget budget = QuicQueuedApplicationSendBudget.AllowSingleDatagram(128);
        RecordingTurnPlanner planner = new(selectedWriteIndex: 2);

        QuicApplicationSendPlan plan = QuicApplicationSendTurnPlannerDispatch.SelectQueuedApplicationSendPlan(
            planner,
            planningSnapshot,
            budget,
            out _,
            out Exception? exception);

        Assert.Equal(QuicApplicationSendPlanKind.None, plan.Kind);
        Assert.Equal(QuicSendPolicyBlockedReason.InvalidQueuedApplicationSend, plan.BlockedReason);
        Assert.IsType<InvalidOperationException>(exception);
        Assert.Equal(originalOrder, planningSnapshot);
    }

    [Fact]
    public void AlternateTurnPlannerCanStopBeforeRuntimeBudgetIsExhausted()
    {
        QuicApplicationSendTurnContext context = new(4, 3, 1, QuicQueuedApplicationSendBudget.Allowed(4, 4096));
        RecordingTurnPlanner planner = new(selectedWriteIndex: 0, shouldScheduleNext: false);

        Assert.False(QuicApplicationSendTurnPlannerDispatch.ShouldScheduleNext(planner, context));
    }

    [Fact]
    public void RuntimeRetainsTheInjectedConnectionLocalTurnPlanner()
    {
        RecordingTurnPlanner planner = new(selectedWriteIndex: 0);

        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            applicationSendTurnPlanner: planner);

        Assert.Same(planner, runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    public void ForcedConservativeTurnPolicyUsesTheCurrentPlannerAndCanOnlyBeConfiguredOnce()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        runtime.ConfigureApplicationSendTurnPolicyMode(QuicApplicationSendTurnPolicyMode.Conservative);

        Assert.Equal(QuicApplicationSendTurnPolicyMode.Conservative, runtime.ApplicationSendTurnPolicyMode);
        Assert.Same(QuicCurrentApplicationSendTurnPlanner.Instance, runtime.ApplicationSendTurnPlanner);
        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureApplicationSendTurnPolicyMode(QuicApplicationSendTurnPolicyMode.LegacyCurrent));
    }

    [Fact]
    public void ForcedLegacyTurnPolicyPreservesTheNullPlannerFastPath()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        runtime.ConfigureApplicationSendTurnPolicyMode(QuicApplicationSendTurnPolicyMode.LegacyCurrent);

        Assert.Equal(QuicApplicationSendTurnPolicyMode.LegacyCurrent, runtime.ApplicationSendTurnPolicyMode);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    public void AdaptiveRuntimeOptionsApplyTheForcedTurnPolicyBeforeTraffic()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            ForcedApplicationSendTurnPolicyMode = QuicApplicationSendTurnPolicyMode.Conservative,
        };

        runtime.ConfigureAdaptiveRuntimePolicy(options);

        Assert.Equal(QuicApplicationSendTurnPolicyMode.Conservative, runtime.ApplicationSendTurnPolicyMode);
        Assert.Same(QuicCurrentApplicationSendTurnPlanner.Instance, runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    public void AdaptiveRuntimeShadowRejectsANonlegacyForcedTurnPolicy()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            AdaptiveRuntimeShadowEnabled = true,
            ForcedApplicationSendTurnPolicyMode = QuicApplicationSendTurnPolicyMode.Conservative,
        };

        Assert.Throws<InvalidOperationException>(() => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(QuicApplicationSendTurnPolicyMode.LegacyCurrent, runtime.ApplicationSendTurnPolicyMode);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    public void ForcedTurnPolicyCannotReplaceAnInjectedPlanner()
    {
        RecordingTurnPlanner planner = new(selectedWriteIndex: 0);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            applicationSendTurnPlanner: planner);

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureApplicationSendTurnPolicyMode(QuicApplicationSendTurnPolicyMode.Conservative));
        Assert.Same(planner, runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    public void ListenerFactoryCreatesDistinctTurnPlannersPerConnection()
    {
        int factoryCallCount = 0;
        using QuicListenerHost listenerHost = new(
            new IPEndPoint(IPAddress.Loopback, 0),
            [SslApplicationProtocol.Http3],
            (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions()),
            listenBacklog: 1,
            applicationSendTurnPlannerFactory: () =>
            {
                factoryCallCount++;
                return new RecordingTurnPlanner(selectedWriteIndex: 0);
            });

        using QuicConnectionRuntime firstRuntime = listenerHost.CreateRuntime(new QuicServerConnectionOptions());
        using QuicConnectionRuntime secondRuntime = listenerHost.CreateRuntime(new QuicServerConnectionOptions());

        Assert.Equal(2, factoryCallCount);
        Assert.IsType<RecordingTurnPlanner>(firstRuntime.ApplicationSendTurnPlanner);
        Assert.IsType<RecordingTurnPlanner>(secondRuntime.ApplicationSendTurnPlanner);
        Assert.NotSame(firstRuntime.ApplicationSendTurnPlanner, secondRuntime.ApplicationSendTurnPlanner);
    }

    private static PendingApplicationSendRequest CreateQueuedWrite(
        long sequence,
        ulong streamId,
        int dataLength,
        bool fin = false)
    {
        byte[] streamPayload = CreateQueuedWritePayload(streamId, dataLength, fin);
        return new PendingApplicationSendRequest(
            sequence,
            streamId,
            Priority: 0,
            streamPayload,
            streamPayload.Length);
    }

    private static byte[] CreateQueuedWritePayload(ulong streamId, int dataLength, bool fin = false)
    {
        byte[] streamData = Enumerable.Range(0, dataLength).Select(value => (byte)value).ToArray();
        byte[] streamPayload = new byte[dataLength + 32];

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum
                | QuicStreamFrameBits.LengthBitMask
                | (fin ? QuicStreamFrameBits.FinBitMask : 0)),
            streamId,
            offset: 0,
            streamData,
            streamPayload,
            out int streamPayloadLength));

        return streamPayload[..streamPayloadLength];
    }

    private sealed class RecordingTurnPlanner(int selectedWriteIndex, bool shouldScheduleNext = true) : IQuicApplicationSendTurnPlanner
    {
        internal int SelectionCount { get; private set; }

        public bool ShouldScheduleNext(in QuicApplicationSendTurnContext context)
            => shouldScheduleNext;

        public int SelectFirstQueuedWriteIndex(
            ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites,
            QuicQueuedApplicationSendBudget budget)
        {
            SelectionCount++;
            return selectedWriteIndex;
        }
    }
}

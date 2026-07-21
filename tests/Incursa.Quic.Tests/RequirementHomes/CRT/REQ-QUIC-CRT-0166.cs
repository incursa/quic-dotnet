// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0166")]
public sealed class REQ_QUIC_CRT_0166
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeShadowExactlyReproducesTheFrozenLegacySelector()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        RegisterDistinctStreamObservers(runtime, count: 15);
        runtime.EnableAdaptiveRuntimeShadow();

        clock.Advance(Stopwatch.Frequency);
        Assert.True(runtime.TryCaptureReceiveCreditShadowAtActorBoundary(
            clock.Ticks,
            out _,
            out QuicReceiveCreditPolicySnapshot immediateSnapshot));
        Assert.False(runtime.ShouldUseBatchedReceiveCreditPath());
        Assert.Equal(QuicReceiveCreditPolicyMode.LegacyCurrent, immediateSnapshot.AppliedPolicy);
        Assert.Equal(QuicReceiveCreditPolicyMode.Immediate, immediateSnapshot.ProposedPolicy);
        Assert.Equal(QuicAdaptiveRuntimePolicyReason.LegacyImmediate, immediateSnapshot.Reason);

        _ = runtime.RegisterStreamObserver(streamId: 60, static _ => { });
        clock.Advance(Stopwatch.Frequency);
        Assert.True(runtime.TryCaptureReceiveCreditShadowAtActorBoundary(
            clock.Ticks,
            out _,
            out QuicReceiveCreditPolicySnapshot batchedSnapshot));
        Assert.True(runtime.ShouldUseBatchedReceiveCreditPath());
        Assert.Equal(QuicReceiveCreditPolicyMode.LegacyCurrent, batchedSnapshot.AppliedPolicy);
        Assert.Equal(QuicReceiveCreditPolicyMode.ReadDominantBatch, batchedSnapshot.ProposedPolicy);
        Assert.Equal(QuicAdaptiveRuntimePolicyReason.LegacyReadDominantBatch, batchedSnapshot.Reason);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ShadowPreservesTheStickyApplicationWriteFallback()
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        runtime.SetStreamWriteDispatcher(static (_, _, _, _, _) => true);
        RegisterDistinctStreamObservers(runtime, count: 16);
        runtime.EnableAdaptiveRuntimeShadow();
        long firstEndTicks = Stopwatch.GetTimestamp() + Stopwatch.Frequency;

        Assert.True(runtime.TryCaptureReceiveCreditShadowAtActorBoundary(
            firstEndTicks,
            out _,
            out QuicReceiveCreditPolicySnapshot beforeWrite));
        Assert.Equal(QuicReceiveCreditPolicyMode.ReadDominantBatch, beforeWrite.ProposedPolicy);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(true, out QuicStreamId streamId, out _));

        Task write = runtime.WriteStreamAsync(streamId.Value, new byte[1024], CancellationToken.None).AsTask();

        Assert.True(runtime.TryCaptureReceiveCreditShadowAtActorBoundary(
            firstEndTicks + Stopwatch.Frequency,
            out _,
            out QuicReceiveCreditPolicySnapshot afterWrite));
        Assert.False(runtime.ShouldUseBatchedReceiveCreditPath());
        Assert.Equal(QuicReceiveCreditPolicyMode.LegacyCurrent, afterWrite.AppliedPolicy);
        Assert.Equal(QuicReceiveCreditPolicyMode.Immediate, afterWrite.ProposedPolicy);
        Assert.True(afterWrite.HasIssuedApplicationData);

        await runtime.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => write.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShadowProposalHasNoRuntimeBehaviorConsumer()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicReceiveCreditShadowController controller = default;
        QuicAdaptiveRuntimeConnectionObservation observation =
            QuicAdaptiveRuntimeShadowTestSupport.CreateObservation(epochSequence: 1, liveObserverStreams: 16);

        Assert.True(controller.TryEvaluate(in observation, out QuicReceiveCreditPolicySnapshot snapshot));

        Assert.Equal(QuicReceiveCreditPolicyMode.ReadDominantBatch, snapshot.ProposedPolicy);
        Assert.False(runtime.ShouldUseBatchedReceiveCreditPath());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShadowAndForcedModesCannotBeCombined()
    {
        using QuicConnectionRuntime forcedRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        forcedRuntime.ConfigureReceiveCreditPolicyMode(QuicReceiveCreditPolicyMode.Immediate);
        Assert.Throws<InvalidOperationException>(forcedRuntime.EnableAdaptiveRuntimeShadow);

        using QuicConnectionRuntime shadowRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        shadowRuntime.EnableAdaptiveRuntimeShadow();
        Assert.Throws<InvalidOperationException>(
            () => shadowRuntime.ConfigureReceiveCreditPolicyMode(QuicReceiveCreditPolicyMode.ReadDominantBatch));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InternalConnectionOptionsRejectForcedCandidateWithShadow()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicServerConnectionOptions options = new()
        {
            ForcedReceiveCreditPolicyMode = QuicReceiveCreditPolicyMode.ReadDominantBatch,
            AdaptiveRuntimeShadowEnabled = true,
        };

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));

        Assert.Equal(
            "Adaptive runtime shadow requires the legacy_current receive-credit policy.",
            exception.Message);
        Assert.False(runtime.ShouldUseBatchedReceiveCreditPath());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConfiguredShadowSinkPublishesOnlyAtBoundedActorIntervals()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        RecordingShadowEpochSink sink = new();
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        RegisterDistinctStreamObservers(runtime, count: 16);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            ForcedReceiveCreditPolicyMode = QuicReceiveCreditPolicyMode.LegacyCurrent,
            AdaptiveRuntimeShadowEnabled = true,
            AdaptiveRuntimeShadowEpochInterval = TimeSpan.FromMilliseconds(250),
            AdaptiveRuntimeShadowEpochSink = sink,
        });

        clock.Advance(Stopwatch.Frequency / 8);
        runtime.TryPublishReceiveCreditShadowAtActorBoundary(clock.Ticks);
        Assert.Empty(sink.Epochs);

        clock.Advance(Stopwatch.Frequency / 8);
        runtime.TryPublishReceiveCreditShadowAtActorBoundary(clock.Ticks);
        QuicReceiveCreditPolicySnapshot first = Assert.Single(sink.Epochs).Snapshot;
        Assert.Equal(1UL, first.EpochSequence);
        Assert.Equal(QuicReceiveCreditPolicyMode.LegacyCurrent, first.AppliedPolicy);
        Assert.Equal(QuicReceiveCreditPolicyMode.ReadDominantBatch, first.ProposedPolicy);

        runtime.TryPublishReceiveCreditShadowAtActorBoundary(clock.Ticks);
        Assert.Single(sink.Epochs);

        clock.Advance(Stopwatch.Frequency / 4);
        runtime.TryPublishReceiveCreditShadowAtActorBoundary(clock.Ticks);
        Assert.Equal(2, sink.Epochs.Count);
        Assert.Equal(2UL, sink.Epochs[1].Snapshot.EpochSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShadowSinkFailureCannotEscapeTheActorBoundary()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            AdaptiveRuntimeShadowEnabled = true,
            AdaptiveRuntimeShadowEpochInterval = TimeSpan.FromMilliseconds(250),
            AdaptiveRuntimeShadowEpochSink = new ThrowingShadowEpochSink(),
        });

        clock.Advance(Stopwatch.Frequency / 4);
        runtime.TryPublishReceiveCreditShadowAtActorBoundary(clock.Ticks);

        Assert.False(runtime.ShouldUseBatchedReceiveCreditPath());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EpochExportCannotBeConfiguredOutsideShadowMode()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicServerConnectionOptions options = new()
        {
            AdaptiveRuntimeShadowEpochInterval = TimeSpan.FromMilliseconds(250),
            AdaptiveRuntimeShadowEpochSink = new RecordingShadowEpochSink(),
        };

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));

        Assert.Equal("Adaptive runtime shadow epoch export requires shadow mode.", exception.Message);
    }

    private static void RegisterDistinctStreamObservers(QuicConnectionRuntime runtime, int count)
    {
        for (int index = 0; index < count; index++)
        {
            _ = runtime.RegisterStreamObserver((ulong)(index * 4), static _ => { });
        }
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        internal FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; private set; }

        public double Seconds => Ticks / (double)Stopwatch.Frequency;

        internal void Advance(long ticks)
        {
            Ticks += ticks;
        }
    }

    private sealed class RecordingShadowEpochSink : IQuicAdaptiveRuntimeShadowEpochSink
    {
        internal List<(QuicAdaptiveRuntimeConnectionObservation Observation, QuicReceiveCreditPolicySnapshot Snapshot)> Epochs { get; } = [];

        public bool TryPublish(
            in QuicAdaptiveRuntimeConnectionObservation observation,
            in QuicReceiveCreditPolicySnapshot snapshot)
        {
            Epochs.Add((observation, snapshot));
            return true;
        }
    }

    private sealed class ThrowingShadowEpochSink : IQuicAdaptiveRuntimeShadowEpochSink
    {
        public bool TryPublish(
            in QuicAdaptiveRuntimeConnectionObservation observation,
            in QuicReceiveCreditPolicySnapshot snapshot)
            => throw new InvalidOperationException("diagnostic sink failure");
    }
}

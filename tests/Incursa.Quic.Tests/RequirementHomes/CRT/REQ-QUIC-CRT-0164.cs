// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0164")]
public sealed class REQ_QUIC_CRT_0164
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DisabledObservationDoesNotCaptureOrAdvanceAnEpoch()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        Assert.False(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(
            clock.Ticks + Stopwatch.Frequency,
            out QuicAdaptiveRuntimeConnectionObservation disabledObservation));
        Assert.Equal(default, disabledObservation);

        clock.Advance(Stopwatch.Frequency);
        runtime.EnableAdaptiveRuntimeObservation();
        clock.Advance(Stopwatch.Frequency);

        Assert.True(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(
            clock.Ticks,
            out QuicAdaptiveRuntimeConnectionObservation firstObservation));
        Assert.Equal(1UL, firstObservation.ConnectionEpochSequence);
        Assert.Equal(Stopwatch.Frequency * 2L, firstObservation.EpochStartTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ObservationUsesVersionedBoundedConnectionLocalInputs()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        RegisterDistinctStreamObservers(runtime, count: 16);
        runtime.EnableAdaptiveRuntimeObservation();
        clock.Advance(Stopwatch.Frequency / 4);

        Assert.True(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(
            clock.Ticks,
            out QuicAdaptiveRuntimeConnectionObservation observation));

        Assert.Equal(1UL, observation.ConnectionEpochSequence);
        Assert.Equal(Stopwatch.Frequency, observation.EpochStartTicks);
        Assert.Equal(clock.Ticks, observation.EpochEndTicks);
        Assert.Equal(250_000UL, observation.ActiveDurationMicros);
        Assert.Equal(
            QuicAdaptiveRuntimeConnectionObservation.CurrentObservationContractVersion,
            observation.ObservationContractVersion);
        Assert.Equal(
            QuicAdaptiveRuntimeConnectionObservation.CurrentPolicyRuleVersion,
            observation.PolicyRuleVersion);
        Assert.Null(observation.AdvisorAgeMicros);
        Assert.Equal(QuicAdaptiveRuntimeSignalMask.QueueDelayEwma, observation.MissingSignalMask);
        Assert.Equal(QuicAdaptiveRuntimeSignalMask.None, observation.StaleSignalMask);
        Assert.Equal(QuicAdaptiveRuntimeLifecycle.Establishing, observation.LifecycleFlags);
        Assert.False(observation.HasIssuedApplicationData);
        Assert.Equal(0, observation.OpenStreams);
        Assert.Equal(16, observation.LiveObserverStreams);
        Assert.Equal(0U, observation.QueuedApplicationWrites);
        Assert.Equal(0U, observation.QueueDelayEwmaMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DuplicateAndOutOfOrderEpochBoundariesAreRejected()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        runtime.EnableAdaptiveRuntimeObservation();
        long firstEndTicks = clock.Ticks + Stopwatch.Frequency;

        Assert.True(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(firstEndTicks, out _));
        Assert.False(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(firstEndTicks, out _));
        Assert.False(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(firstEndTicks - 1, out _));

        Assert.True(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(
            firstEndTicks + Stopwatch.Frequency,
            out QuicAdaptiveRuntimeConnectionObservation secondObservation));
        Assert.Equal(2UL, secondObservation.ConnectionEpochSequence);
        Assert.Equal(firstEndTicks, secondObservation.EpochStartTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AvailableQueueDelayIsCapturedWithoutAMissingSignal()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        runtime.ObserveApplicationSendWorkItemQueueDelay(queueDelayMilliseconds: 2.5);
        runtime.EnableAdaptiveRuntimeObservation();
        clock.Advance(Stopwatch.Frequency);

        Assert.True(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(
            clock.Ticks,
            out QuicAdaptiveRuntimeConnectionObservation observation));

        Assert.Equal(QuicAdaptiveRuntimeSignalMask.None, observation.MissingSignalMask);
        Assert.Equal(2_500U, observation.QueueDelayEwmaMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task PositiveApplicationWriteIsCapturedAsAStickyConnectionFact()
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        runtime.SetStreamWriteDispatcher(static (_, _, _, _, _) => true);
        runtime.EnableAdaptiveRuntimeObservation();
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(true, out QuicStreamId streamId, out _));

        Task write = runtime.WriteStreamAsync(streamId.Value, new byte[1024], CancellationToken.None).AsTask();

        Assert.True(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(
            Stopwatch.GetTimestamp() + Stopwatch.Frequency,
            out QuicAdaptiveRuntimeConnectionObservation observation));
        Assert.True(observation.HasIssuedApplicationData);

        await runtime.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => write.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ObservationCanOnlyBeEnabledOnce()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.EnableAdaptiveRuntimeObservation();

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            runtime.EnableAdaptiveRuntimeObservation);

        Assert.Equal("Adaptive runtime observation has already been enabled.", exception.Message);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void SteadyStateCaptureDoesNotAllocate()
    {
        FakeMonotonicClock clock = new(Stopwatch.Frequency);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        runtime.EnableAdaptiveRuntimeObservation();
        Assert.True(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(++clock.Ticks, out _));

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int index = 0; index < 1024; index++)
        {
            Assert.True(runtime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(++clock.Ticks, out _));
        }

        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(allocatedBefore, allocatedAfter);
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

        public long Ticks { get; set; }

        public double Seconds => Ticks / (double)Stopwatch.Frequency;

        internal void Advance(long ticks)
        {
            Ticks += ticks;
        }
    }
}

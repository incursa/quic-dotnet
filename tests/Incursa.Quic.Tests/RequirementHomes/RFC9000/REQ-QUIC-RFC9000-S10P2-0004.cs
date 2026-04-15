using System;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2-0004">Once its closing or draining state ends, an endpoint SHOULD discard all connection state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2-0004")]
public sealed class REQ_QUIC_RFC9000_S10P2_0004
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TerminalLifetimeExpiryDiscardsTheConnection(bool useLocalCloseRequest)
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        ApplyTerminalTransition(runtime, useLocalCloseRequest, nowTicks: 1);

        QuicConnectionTimerKind timerKind = useLocalCloseRequest
            ? QuicConnectionTimerKind.CloseLifetime
            : QuicConnectionTimerKind.DrainLifetime;

        long dueTicks = runtime.TimerState.GetDueTicks(timerKind)!.Value;
        ulong generation = runtime.TimerState.GetGeneration(timerKind);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks,
                timerKind,
                generation),
            nowTicks: dueTicks);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EnteringTerminalStateDoesNotDiscardImmediately(bool useLocalCloseRequest)
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult result = ApplyTerminalTransition(runtime, useLocalCloseRequest, nowTicks: 1);

        Assert.NotEqual(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    private static QuicConnectionTransitionResult ApplyTerminalTransition(
        QuicConnectionRuntime runtime,
        bool useLocalCloseRequest,
        long nowTicks)
    {
        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.NoError,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: useLocalCloseRequest ? "closing" : "draining");

        return useLocalCloseRequest
            ? runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    ObservedAtTicks: nowTicks,
                    closeMetadata),
                nowTicks)
            : runtime.Transition(
                new QuicConnectionConnectionCloseFrameReceivedEvent(
                    ObservedAtTicks: nowTicks,
                    closeMetadata),
                nowTicks);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 100);

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 200,
                PeerMaxIdleTimeoutMicros: 200,
                CurrentProbeTimeoutMicros: 100),
            nowTicks: 0);

        return runtime;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}

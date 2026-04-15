using System.Diagnostics;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2-0001">These states SHOULD persist for at least three times the current PTO interval as defined in [QUIC-RECOVERY].</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2-0001")]
public sealed class REQ_QUIC_RFC9000_S10P2_0001
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EnteringClosingOrDrainingState_ArmsTheTerminalLifetimeAtThreeTimesTheCurrentPto(
        bool useLocalCloseRequest)
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = CreateRuntime(
            clock,
            localMaxIdleTimeoutMicros: 1,
            peerMaxIdleTimeoutMicros: 2,
            currentProbeTimeoutMicros: 100);

        long nowTicks = MicrosecondsToTicks(25);
        QuicConnectionTimerKind timerKind = useLocalCloseRequest
            ? QuicConnectionTimerKind.CloseLifetime
            : QuicConnectionTimerKind.DrainLifetime;
        ApplyTerminalTransition(runtime, useLocalCloseRequest, nowTicks);

        long dueTicks = runtime.TimerState.GetDueTicks(timerKind)!.Value;
        long expectedLifetimeTicks = MicrosecondsToTicks(300);

        Assert.Equal(expectedLifetimeTicks, dueTicks - nowTicks);
        Assert.Equal(useLocalCloseRequest ? QuicConnectionPhase.Closing : QuicConnectionPhase.Draining, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClosingLifetimeIgnoresIdleTimeoutConfiguration()
    {
        FakeMonotonicClock clock = new(0);
        long nowTicks = MicrosecondsToTicks(25);

        QuicConnectionRuntime shortIdleRuntime = CreateRuntime(
            clock,
            localMaxIdleTimeoutMicros: 1,
            peerMaxIdleTimeoutMicros: 2,
            currentProbeTimeoutMicros: 100);
        ApplyTerminalTransition(shortIdleRuntime, useLocalCloseRequest: true, nowTicks);

        QuicConnectionRuntime longIdleRuntime = CreateRuntime(
            clock,
            localMaxIdleTimeoutMicros: 10_000,
            peerMaxIdleTimeoutMicros: 20_000,
            currentProbeTimeoutMicros: 100);
        ApplyTerminalTransition(longIdleRuntime, useLocalCloseRequest: true, nowTicks);

        long shortDueTicks = shortIdleRuntime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;
        long longDueTicks = longIdleRuntime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;

        Assert.Equal(shortDueTicks, longDueTicks);
        Assert.Equal(MicrosecondsToTicks(300), shortDueTicks - nowTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClosingLifetimeSaturatesWhenTheTerminalDeadlineWouldOverflow()
    {
        FakeMonotonicClock clock = new(0);
        long terminalLifetimeTicks = MicrosecondsToTicks(300);
        long nowTicks = long.MaxValue - terminalLifetimeTicks + 1;

        QuicConnectionRuntime runtime = CreateRuntime(
            clock,
            localMaxIdleTimeoutMicros: 1,
            peerMaxIdleTimeoutMicros: 2,
            currentProbeTimeoutMicros: 100);

        ApplyTerminalTransition(runtime, useLocalCloseRequest: true, nowTicks);

        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;

        Assert.Equal(long.MaxValue, dueTicks);
    }

    private static void ApplyTerminalTransition(QuicConnectionRuntime runtime, bool useLocalCloseRequest, long nowTicks)
    {
        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.NoError,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: useLocalCloseRequest ? "closing" : "draining");

        if (useLocalCloseRequest)
        {
            runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    ObservedAtTicks: nowTicks,
                    closeMetadata),
                nowTicks);
            return;
        }

        runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: nowTicks,
                closeMetadata),
            nowTicks);
    }

    private static QuicConnectionRuntime CreateRuntime(
        FakeMonotonicClock clock,
        ulong localMaxIdleTimeoutMicros,
        ulong peerMaxIdleTimeoutMicros,
        ulong currentProbeTimeoutMicros)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: currentProbeTimeoutMicros);

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: localMaxIdleTimeoutMicros,
                PeerMaxIdleTimeoutMicros: peerMaxIdleTimeoutMicros,
                CurrentProbeTimeoutMicros: currentProbeTimeoutMicros),
            nowTicks: 0);

        return runtime;
    }

    private static long MicrosecondsToTicks(ulong micros)
    {
        ulong frequency = (ulong)Stopwatch.Frequency;
        ulong wholeTicks = micros > ulong.MaxValue / frequency
            ? ulong.MaxValue
            : micros * frequency;

        ulong roundedUp = wholeTicks == ulong.MaxValue
            ? wholeTicks
            : wholeTicks + 999_999UL;

        ulong ticks = roundedUp / 1_000_000UL;
        return ticks >= long.MaxValue ? long.MaxValue : (long)ticks;
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

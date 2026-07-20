using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0056")]
public sealed class REQ_QUIC_CRT_0056
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IdleTimeoutExpiresAfterTheRuntimeArmsAndRestartsTheIdleTimer()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = CreateRuntime(clock);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                ReadOnlyMemory<byte>.Empty),
            nowTicks: MicrosecondsToTicks(50));

        long idleDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout)!.Value;
        ulong idleGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.IdleTimeout);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: idleDueTicks,
                QuicConnectionTimerKind.IdleTimeout,
                idleGeneration),
            nowTicks: idleDueTicks);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.IdleTimeout, runtime.TerminalState?.Origin);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void OnlyAllowedLifecycleEventsRearmTheIdleTimer()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = CreateRuntime(clock);

        long initialDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout)!.Value;

        runtime.Transition(
            new QuicConnectionHandshakeConfirmedEvent(ObservedAtTicks: 0),
            nowTicks: MicrosecondsToTicks(25));

        Assert.Equal(initialDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                ReadOnlyMemory<byte>.Empty),
            nowTicks: MicrosecondsToTicks(50));

        long restartedDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout)!.Value;
        Assert.True(restartedDueTicks > initialDueTicks);
    }

    private static QuicConnectionRuntime CreateRuntime(FakeMonotonicClock clock)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 200);

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 300,
                PeerMaxIdleTimeoutMicros: 400,
                CurrentProbeTimeoutMicros: 200),
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
}

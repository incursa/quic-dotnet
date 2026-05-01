using System.Diagnostics;

namespace Incursa.Quic.Tests;

internal static class QuicCrtLifecycleRequirementTestSupport
{
    internal static QuicConnectionRuntime CreateRuntime(QuicCrtLifecycleClock clock)
    {
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

    internal static void ObservePath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        long nowTicks = 1)
    {
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: nowTicks,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks);
    }

    internal static QuicConnectionCloseMetadata CreateLocalClose(string reasonPhrase = "closing")
    {
        return new QuicConnectionCloseMetadata(
            TransportErrorCode: QuicTransportErrorCode.NoError,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: reasonPhrase);
    }

    internal static QuicConnectionCloseMetadata CreatePeerClose(string reasonPhrase = "peer close")
    {
        return new QuicConnectionCloseMetadata(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: reasonPhrase);
    }

    internal static QuicConnectionTransitionResult RequestLocalClose(
        QuicConnectionRuntime runtime,
        long nowTicks = 2)
    {
        return runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: nowTicks,
                CreateLocalClose()),
            nowTicks);
    }

    internal static QuicConnectionTransitionResult ReceivePeerClose(
        QuicConnectionRuntime runtime,
        long nowTicks = 2)
    {
        return runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: nowTicks,
                CreatePeerClose()),
            nowTicks);
    }

    internal static QuicConnectionTransitionResult AcceptStatelessReset(
        QuicConnectionRuntime runtime,
        long nowTicks = 2)
    {
        return runtime.Transition(
            new QuicConnectionAcceptedStatelessResetEvent(
                ObservedAtTicks: nowTicks,
                new QuicConnectionPathIdentity("203.0.113.99"),
                ConnectionId: 99UL),
            nowTicks);
    }

    internal static QuicConnectionTransitionResult ExpireCloseLifetime(QuicConnectionRuntime runtime)
    {
        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;

        return runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks,
                QuicConnectionTimerKind.CloseLifetime,
                runtime.TimerState.GetGeneration(QuicConnectionTimerKind.CloseLifetime)),
            dueTicks);
    }

    internal static QuicConnectionTransitionResult ExpireDrainLifetime(QuicConnectionRuntime runtime)
    {
        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime)!.Value;

        return runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks,
                QuicConnectionTimerKind.DrainLifetime,
                runtime.TimerState.GetGeneration(QuicConnectionTimerKind.DrainLifetime)),
            dueTicks);
    }

    internal static long MicrosecondsToTicks(ulong micros)
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

internal sealed class QuicCrtLifecycleClock : IMonotonicClock
{
    internal QuicCrtLifecycleClock(long ticks)
    {
        Ticks = ticks;
    }

    public long Ticks { get; }

    public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
}

using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0030")]
public sealed class REQ_QUIC_CRT_0030
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CloseLifetimeExpiryDiscardsTheConnection()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = CreateRuntime(clock);

        runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "closing")),
            nowTicks: MicrosecondsToTicks(25));

        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.CloseLifetime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks,
                QuicConnectionTimerKind.CloseLifetime,
                generation),
            nowTicks: dueTicks);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DrainLifetimeExpiryDiscardsTheConnection()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = CreateRuntime(clock);

        runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "draining")),
            nowTicks: MicrosecondsToTicks(25));

        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime)!.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.DrainLifetime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks,
                QuicConnectionTimerKind.DrainLifetime,
                generation),
            nowTicks: dueTicks);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    private static QuicConnectionRuntime CreateRuntime(FakeMonotonicClock clock)
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

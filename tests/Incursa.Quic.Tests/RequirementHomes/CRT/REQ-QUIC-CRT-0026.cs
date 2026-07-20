using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0026")]
public sealed class REQ_QUIC_CRT_0026
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceivedConnectionCloseTransitionsTheRuntimeToDraining()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = CreateRuntime(clock);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.NoError,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "peer close");

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 0,
                closeMetadata),
            nowTicks: MicrosecondsToTicks(75));

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState?.Origin);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.DrainLifetime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DrainingAfterClosingPreservesTheExistingTerminalEndTime()
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
                    ReasonPhrase: "local close")),
            nowTicks: MicrosecondsToTicks(75));

        long closeDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;

        runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "peer close")),
            nowTicks: MicrosecondsToTicks(100));

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime));
        Assert.Equal(closeDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
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

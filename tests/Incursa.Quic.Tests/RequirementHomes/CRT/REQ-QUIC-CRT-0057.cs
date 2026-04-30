using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0057")]
public sealed class REQ_QUIC_CRT_0057
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeTransitionsComputeAndEmitCloseAndDrainDeadlineUpdates()
    {
        FakeMonotonicClock closeClock = new(0);
        using QuicConnectionRuntime closingRuntime = CreateRuntime(closeClock);

        QuicConnectionTransitionResult closeResult = closingRuntime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionCloseMetadata(
                    QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "local close")),
            nowTicks: MicrosecondsToTicks(25));

        QuicConnectionArmTimerEffect closeArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(closeResult.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.CloseLifetime));
        Assert.Equal(closingRuntime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime), closeArm.Priority.DueTicks);

        FakeMonotonicClock drainClock = new(0);
        using QuicConnectionRuntime drainingRuntime = CreateRuntime(drainClock);

        QuicConnectionTransitionResult drainResult = drainingRuntime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionCloseMetadata(
                    QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "peer close")),
            nowTicks: MicrosecondsToTicks(25));

        QuicConnectionArmTimerEffect drainArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(drainResult.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.DrainLifetime));
        Assert.Equal(drainingRuntime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime), drainArm.Priority.DueTicks);
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

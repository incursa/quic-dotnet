using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0055")]
public sealed class REQ_QUIC_CRT_0055
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportParametersCommitDerivesAndArmsTheEffectiveIdleTimeout()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 200);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 300,
                PeerMaxIdleTimeoutMicros: 400,
                CurrentProbeTimeoutMicros: 200),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.NotNull(runtime.IdleTimeoutState);
        Assert.Equal(600UL, runtime.IdleTimeoutState!.EffectiveIdleTimeoutMicros);

        QuicConnectionArmTimerEffect idleArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(result.Effects));

        Assert.Equal(QuicConnectionTimerKind.IdleTimeout, idleArm.TimerKind);
        Assert.Equal(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout), idleArm.Priority.DueTicks);
        Assert.True(idleArm.Priority.DueTicks >= MicrosecondsToTicks(600));
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

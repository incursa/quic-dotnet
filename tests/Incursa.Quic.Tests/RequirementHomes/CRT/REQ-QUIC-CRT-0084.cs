namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0084")]
public sealed class REQ_QUIC_CRT_0084
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AcceptedStatelessResetSuppressesTheOrdinaryCloseHandshake()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionAcceptedStatelessResetEvent(
                ObservedAtTicks: 5,
                new QuicConnectionPathIdentity("203.0.113.41"),
                ConnectionId: 41UL),
            nowTicks: 5);

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Equal(QuicConnectionCloseOrigin.StatelessReset, runtime.TerminalState?.Origin);
        Assert.Equal(QuicConnectionPhase.Draining, result.CurrentPhase);
        Assert.True(result.StateChanged);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.DrainLifetime);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
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

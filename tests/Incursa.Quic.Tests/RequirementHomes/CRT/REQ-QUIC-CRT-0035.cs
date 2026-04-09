namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0035")]
public sealed class REQ_QUIC_CRT_0035
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransitionUsesTheInjectedMonotonicClockAndReturnsExplicitPlumbing()
    {
        FakeMonotonicClock clock = new(123_456_789);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionTransitionResult handshakeResult = runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: -1));

        Assert.Equal(1UL, handshakeResult.Sequence);
        Assert.Equal(clock.Ticks, handshakeResult.ObservedAtTicks);
        Assert.Equal(QuicConnectionEventKind.PeerHandshakeTranscriptCompleted, handshakeResult.EventKind);
        Assert.Equal(QuicConnectionPhase.Establishing, handshakeResult.PreviousPhase);
        Assert.Equal(QuicConnectionPhase.Active, handshakeResult.CurrentPhase);
        Assert.True(handshakeResult.StateChanged);
        Assert.False(handshakeResult.HasEffects);
        Assert.Empty(handshakeResult.Effects);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(clock.Ticks, runtime.LastTransitionTicks);

        QuicConnectionTransitionResult transportResult = runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.DisableActiveMigration),
            nowTicks: 987_654_321);

        Assert.Equal(2UL, transportResult.Sequence);
        Assert.Equal(987_654_321, transportResult.ObservedAtTicks);
        Assert.Equal(QuicConnectionEventKind.TransportParametersCommitted, transportResult.EventKind);
        Assert.True(transportResult.StateChanged);
        Assert.False(transportResult.HasEffects);
        Assert.Empty(transportResult.Effects);
        Assert.Equal(QuicConnectionTransportState.DisableActiveMigration, runtime.TransportFlags);
        Assert.Equal(987_654_321, runtime.LastTransitionTicks);
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

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0066")]
public sealed class REQ_QUIC_CRT_0066
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LocalCloseDoesNotEmitADatagramWhenTheActivePathHasNoAmplificationBudget()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionPathIdentity path = new("203.0.113.30", RemotePort: 443);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, path, ReadOnlyMemory<byte>.Empty),
            nowTicks: 10);

        QuicConnectionCloseMetadata close = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "closing");

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(ObservedAtTicks: 20, close),
            nowTicks: 20);

        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Equal(0UL, runtime.ActivePath!.Value.AmplificationState.SentPayloadBytes);
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

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0060")]
public sealed class REQ_QUIC_CRT_0060
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SuccessfulCandidateValidationUpdatesTheLastValidatedRemoteAddress()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionPathIdentity activePath = new("203.0.113.20", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.21", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, datagram),
            nowTicks: 10);

        Assert.Null(runtime.LastValidatedRemoteAddress);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, candidatePath, datagram),
            nowTicks: 20);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(ObservedAtTicks: 30, candidatePath),
            nowTicks: 30);

        Assert.True(result.StateChanged);
        Assert.Equal(candidatePath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(candidatePath));
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

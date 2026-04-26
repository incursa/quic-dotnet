namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0034")]
public sealed class REQ_QUIC_CRT_0034
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CandidatePathBudgetRejectsAdditionalCandidatesWhenTheBudgetIsFull()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            maximumCandidatePaths: 1);

        QuicConnectionPathIdentity activePath = new("203.0.113.50", RemotePort: 443);
        QuicConnectionPathIdentity firstCandidate = new("203.0.113.51", RemotePort: 443);
        QuicConnectionPathIdentity secondCandidate = new("203.0.113.52", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, datagram),
            nowTicks: 10);

        QuicConnectionTransitionResult firstCandidateResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, firstCandidate, datagram),
            nowTicks: 20);

        QuicConnectionTransitionResult secondCandidateResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 30, secondCandidate, datagram),
            nowTicks: 30);

        Assert.True(firstCandidateResult.StateChanged);
        Assert.Single(runtime.CandidatePaths);
        Assert.Contains(firstCandidate, runtime.CandidatePaths.Keys);

        Assert.False(secondCandidateResult.StateChanged);
        Assert.Single(runtime.CandidatePaths);
        Assert.DoesNotContain(secondCandidate, runtime.CandidatePaths.Keys);
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

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0069")]
public sealed class REQ_QUIC_CRT_0069
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidationSuccessPromotesTheValidatedCandidatePathWhenHandshakeIsConfirmed()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionPathIdentity activePath = new("203.0.113.40", RemotePort: 443);
        QuicConnectionPathIdentity candidatePathIdentity = new("203.0.113.41", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionHandshakeConfirmedEvent(ObservedAtTicks: 5),
            nowTicks: 5);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, datagram),
            nowTicks: 10);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, candidatePathIdentity, datagram),
            nowTicks: 20);

        QuicConnectionTransitionResult validationResult = runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(ObservedAtTicks: 30, candidatePathIdentity),
            nowTicks: 30);

        Assert.True(runtime.HandshakeConfirmed);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(candidatePathIdentity, runtime.ActivePath!.Value.Identity);
        Assert.Null(runtime.ActivePath.Value.RecoverySnapshot);
        Assert.False(runtime.CandidatePaths.ContainsKey(candidatePathIdentity));
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(candidatePathIdentity));
        Assert.Equal(candidatePathIdentity.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == candidatePathIdentity
            && !promote.RestoreSavedState);
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

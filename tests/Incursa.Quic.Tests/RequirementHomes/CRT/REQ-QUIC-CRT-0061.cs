namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0061")]
public sealed class REQ_QUIC_CRT_0061
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecentlyValidatedPathsRemainBoundedAndKeepTheMostRecentEntry()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            maximumRecentlyValidatedPaths: 1);

        QuicConnectionPathIdentity activePath = new("203.0.113.60", RemotePort: 443);
        QuicConnectionPathIdentity firstValidatedPath = new("203.0.113.61", RemotePort: 443);
        QuicConnectionPathIdentity secondValidatedPath = new("203.0.113.62", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, datagram),
            nowTicks: 10);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, firstValidatedPath, datagram),
            nowTicks: 20);

        QuicConnectionTransitionResult firstValidationResult = runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(ObservedAtTicks: 30, firstValidatedPath),
            nowTicks: 30);

        Assert.True(firstValidationResult.StateChanged);
        Assert.Single(runtime.RecentlyValidatedPaths);
        Assert.True(runtime.RecentlyValidatedPaths.TryGetValue(firstValidatedPath, out QuicConnectionValidatedPathRecord firstCachedPath));
        Assert.Equal(firstValidatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Equal(30L, firstCachedPath.LastActivityTicks);
        Assert.Null(firstCachedPath.SavedRecoverySnapshot);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 40, secondValidatedPath, datagram),
            nowTicks: 40);

        QuicConnectionTransitionResult secondValidationResult = runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(ObservedAtTicks: 50, secondValidatedPath),
            nowTicks: 50);

        Assert.True(secondValidationResult.StateChanged);
        Assert.Single(runtime.RecentlyValidatedPaths);
        Assert.True(runtime.RecentlyValidatedPaths.TryGetValue(secondValidatedPath, out QuicConnectionValidatedPathRecord secondCachedPath));
        Assert.DoesNotContain(firstValidatedPath, runtime.RecentlyValidatedPaths.Keys);
        Assert.Equal(secondValidatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Equal(50L, secondCachedPath.LastActivityTicks);
        Assert.Null(secondCachedPath.SavedRecoverySnapshot);
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

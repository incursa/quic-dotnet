namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0064")]
public sealed class REQ_QUIC_CRT_0064
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ValidationBeforePeerHandshakeTranscriptCompletionDoesNotPromoteThePath()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionPathIdentity activePath = new("203.0.113.20", RemotePort: 443);
        QuicConnectionPathIdentity candidatePathIdentity = new("203.0.113.21", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, datagram),
            nowTicks: 10);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, candidatePathIdentity, datagram),
            nowTicks: 20);

        QuicConnectionTransitionResult validationResult = runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(ObservedAtTicks: 30, candidatePathIdentity),
            nowTicks: 30);

        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.ActivePath.Value.IsValidated);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePathIdentity, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.True(candidatePath.AmplificationState.IsAddressValidated);
        Assert.Equal(candidatePathIdentity.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(candidatePathIdentity));

        Assert.DoesNotContain(validationResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);

        QuicConnectionTransitionResult handshakeResult = runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 40),
            nowTicks: 40);

        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(candidatePathIdentity, runtime.ActivePath!.Value.Identity);
        Assert.Null(runtime.ActivePath.Value.RecoverySnapshot);
        Assert.False(runtime.CandidatePaths.ContainsKey(candidatePathIdentity));
        Assert.Contains(handshakeResult.Effects, effect =>
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

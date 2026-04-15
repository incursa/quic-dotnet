namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0007")]
public sealed class REQ_QUIC_RFC9000_S9P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketFromANewAddressStartsPathValidationWhenMigrationIsPermitted()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionPathIdentity activePath = new("203.0.113.70", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.71", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 5),
            nowTicks: 5).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, datagram),
            nowTicks: 10).StateChanged);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, candidatePath.Validation.ChallengePayload.Length);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath
            && send.Datagram.Length == QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedPacketsDoNotRestartPathValidationWhileTheChallengeIsPending()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionPathIdentity activePath = new("203.0.113.80", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.81", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 5),
            nowTicks: 5).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, datagram),
            nowTicks: 10).StateChanged);

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20);

        Assert.Contains(firstResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        long? validationDeadline = candidatePath.Validation.ValidationDeadlineTicks;

        QuicConnectionTransitionResult repeatResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 30, migratedPath, datagram),
            nowTicks: 30);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord repeatedCandidatePath));
        Assert.Equal(1UL, repeatedCandidatePath.Validation.ChallengeSendCount);
        Assert.Equal(validationDeadline, repeatedCandidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(repeatResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
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

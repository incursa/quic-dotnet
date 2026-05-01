namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0068")]
public sealed class REQ_QUIC_CRT_0068
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CandidatePathTracksChallengePayloadSendCountDeadlineAndTerminalOutcome()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionPathIdentity activePath = new("203.0.113.50", RemotePort: 443);
        QuicConnectionPathIdentity changedPath = new("203.0.113.51", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, datagram),
            nowTicks: 10);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, changedPath, datagram),
            nowTicks: 20);

        Assert.True(runtime.CandidatePaths.TryGetValue(changedPath, out QuicConnectionCandidatePathRecord pendingCandidate));
        Assert.Equal(1UL, pendingCandidate.Validation.ChallengeSendCount);
        Assert.Equal(20L, pendingCandidate.Validation.ChallengeSentAtTicks);
        Assert.True(pendingCandidate.Validation.ValidationDeadlineTicks > 20L);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, pendingCandidate.Validation.ChallengePayload.Length);
        Assert.False(pendingCandidate.Validation.IsValidated);
        Assert.False(pendingCandidate.Validation.IsAbandoned);

        runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 30,
                changedPath,
                IsAbandoned: true),
            nowTicks: 30);

        Assert.True(runtime.CandidatePaths.TryGetValue(changedPath, out QuicConnectionCandidatePathRecord abandonedCandidate));
        Assert.True(abandonedCandidate.Validation.IsAbandoned);
        Assert.False(abandonedCandidate.Validation.IsValidated);
        Assert.Null(abandonedCandidate.Validation.ValidationDeadlineTicks);
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

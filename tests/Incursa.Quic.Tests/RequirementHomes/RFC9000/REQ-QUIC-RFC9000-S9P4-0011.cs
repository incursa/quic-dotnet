namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0011")]
public sealed class REQ_QUIC_RFC9000_S9P4_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TimerRetryRearmsTheNextDeadlineAfterTheCurrentDeadline()
    {
        (QuicConnectionRuntime runtime, QuicConnectionPathIdentity candidatePath, long initialDeadlineTicks, ulong initialTimerGeneration, long initialChallengeSentAtTicks) =
            CreatePendingPathValidation();

        long initialIntervalTicks = initialDeadlineTicks - initialChallengeSentAtTicks;
        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: initialDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                initialTimerGeneration),
            nowTicks: initialDeadlineTicks);

        Assert.Contains(retryResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == candidatePath);
        Assert.Contains(retryResult.Effects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.PathValidation);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord retriedCandidate));
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.Value > initialDeadlineTicks);
        Assert.True(retriedCandidate.Validation.ChallengeSentAtTicks.HasValue);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.Value - retriedCandidate.Validation.ChallengeSentAtTicks.Value >= initialIntervalTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TimerRetryDoesNotShortenTheInitialInterval()
    {
        (QuicConnectionRuntime runtime, QuicConnectionPathIdentity candidatePath, long initialDeadlineTicks, ulong initialTimerGeneration, long initialChallengeSentAtTicks) =
            CreatePendingPathValidation();

        long initialIntervalTicks = initialDeadlineTicks - initialChallengeSentAtTicks;
        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: initialDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                initialTimerGeneration),
            nowTicks: initialDeadlineTicks);

        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord retriedCandidate));
        Assert.Equal(2UL, retriedCandidate.Validation.ChallengeSendCount);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.True(retriedCandidate.Validation.ChallengeSentAtTicks.HasValue);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.Value - retriedCandidate.Validation.ChallengeSentAtTicks.Value >= initialIntervalTicks);
        Assert.Contains(retryResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == candidatePath);
    }

    private static (QuicConnectionRuntime Runtime, QuicConnectionPathIdentity CandidatePath, long DeadlineTicks, ulong TimerGeneration, long ChallengeSentAtTicks) CreatePendingPathValidation()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.40", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.41", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                candidatePath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord candidate));
        Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.True(candidate.Validation.ChallengeSentAtTicks.HasValue);

        return (
            runtime,
            candidatePath,
            candidate.Validation.ValidationDeadlineTicks.Value,
            runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation),
            candidate.Validation.ChallengeSentAtTicks.Value);
    }
}

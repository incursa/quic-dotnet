namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0009")]
public sealed class REQ_QUIC_RFC9000_S9P4_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TimerExpiryAtTheDeadlineRetransmitsAChallengeAndRearmsTheTimer()
    {
        (QuicConnectionRuntime runtime, QuicConnectionPathIdentity candidatePath, long initialDeadlineTicks, ulong initialTimerGeneration, long initialChallengeSentAtTicks, byte[] initialChallengePayload) =
            CreatePendingPathValidation();

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: initialDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                initialTimerGeneration),
            nowTicks: initialDeadlineTicks);

        QuicConnectionSendDatagramEffect retrySend = Assert.Single(
            retryResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        Assert.Equal(candidatePath, retrySend.PathIdentity);
        Assert.Contains(retryResult.Effects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.PathValidation);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord retriedCandidate));
        Assert.Equal(2UL, retriedCandidate.Validation.ChallengeSendCount);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.Value > initialDeadlineTicks);
        Assert.True(retriedCandidate.Validation.ChallengeSentAtTicks.HasValue);
        Assert.False(initialChallengePayload.AsSpan().SequenceEqual(retriedCandidate.Validation.ChallengePayload.Span));

        long initialIntervalTicks = initialDeadlineTicks - initialChallengeSentAtTicks;
        long retryIntervalTicks = retriedCandidate.Validation.ValidationDeadlineTicks.Value - retriedCandidate.Validation.ChallengeSentAtTicks.Value;

        Assert.Equal(initialIntervalTicks, retryIntervalTicks);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);
        Assert.True(runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation) > initialTimerGeneration);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StaleTimerAfterTheResponseDoesNotRetransmit()
    {
        (QuicConnectionRuntime runtime, QuicConnectionPathIdentity candidatePath, long initialDeadlineTicks, ulong initialTimerGeneration, _, _) =
            CreatePendingPathValidation();

        long responseTicks = initialDeadlineTicks - 1;
        Assert.True(runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(
                ObservedAtTicks: responseTicks,
                candidatePath),
            nowTicks: responseTicks).StateChanged);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));

        QuicConnectionTransitionResult staleTimerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: initialDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                initialTimerGeneration),
            nowTicks: initialDeadlineTicks);

        Assert.False(staleTimerResult.StateChanged);
        Assert.DoesNotContain(staleTimerResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    private static (QuicConnectionRuntime Runtime, QuicConnectionPathIdentity CandidatePath, long DeadlineTicks, ulong TimerGeneration, long ChallengeSentAtTicks, byte[] ChallengePayload) CreatePendingPathValidation()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.20", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.21", RemotePort: 443);
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
            candidate.Validation.ChallengeSentAtTicks.Value,
            candidate.Validation.ChallengePayload.ToArray());
    }
}

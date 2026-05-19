namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P2P1-0001")]
public sealed class REQ_QUIC_RFC9000_S8P2P1_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathValidationTimerCanSendAnotherPathChallengeToCoverLoss()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.121", RemotePort: 443);

        QuicConnectionTransitionResult firstResult =
            QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(firstResult, candidatePath, runtime: runtime);

        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord firstCandidate));
        byte[] firstChallengeData = firstCandidate.Validation.ChallengePayload.ToArray();
        Assert.True(firstCandidate.Validation.ValidationDeadlineTicks.HasValue);
        long firstDeadlineTicks = firstCandidate.Validation.ValidationDeadlineTicks.Value;
        ulong firstGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: firstDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                firstGeneration),
            nowTicks: firstDeadlineTicks);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(retryResult, candidatePath, runtime: runtime);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord retryCandidate));
        Assert.Equal(2UL, retryCandidate.Validation.ChallengeSendCount);
        Assert.False(firstChallengeData.AsSpan().SequenceEqual(retryCandidate.Validation.ChallengePayload.Span));
    }
}

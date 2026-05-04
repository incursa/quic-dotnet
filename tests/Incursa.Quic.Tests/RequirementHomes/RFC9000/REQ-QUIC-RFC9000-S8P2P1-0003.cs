namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P2P1-0003")]
public sealed class REQ_QUIC_RFC9000_S8P2P1_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathValidationTimerExpirySendsTheNextProbeAtTheArmedCadence()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.124", RemotePort: 443);

        QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord candidate));
        Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: candidate.Validation.ValidationDeadlineTicks.Value,
                QuicConnectionTimerKind.PathValidation,
                runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation)),
            nowTicks: candidate.Validation.ValidationDeadlineTicks.Value);

        Assert.True(retryResult.StateChanged);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(retryResult, candidatePath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedPacketsBeforeTheValidationDeadlineDoNotSendAnotherProbe()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.125", RemotePort: 443);

        QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord candidate));
        Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);

        long beforeDeadlineTicks = candidate.Validation.ValidationDeadlineTicks.Value > 20
            ? candidate.Validation.ValidationDeadlineTicks.Value - 1
            : 20;
        QuicConnectionTransitionResult repeatedPacketResult =
            QuicS8P2PathValidationTestSupport.StartCandidatePath(
                runtime,
                candidatePath,
                observedAtTicks: beforeDeadlineTicks);

        Assert.True(repeatedPacketResult.StateChanged);
        Assert.DoesNotContain(
            repeatedPacketResult.Effects,
            effect => effect is QuicConnectionSendDatagramEffect send
                && QuicS8P2PathValidationTestSupport.CountPathChallengeFrames(send.Datagram.Span) > 0);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord repeatedCandidate));
        Assert.Equal(1UL, repeatedCandidate.Validation.ChallengeSendCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TimerAtTheExactValidationDeadlineSendsOneProbeAndRearmsLater()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.126", RemotePort: 443);

        QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord candidate));
        Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);
        long exactDeadlineTicks = candidate.Validation.ValidationDeadlineTicks.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: exactDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                generation),
            nowTicks: exactDeadlineTicks);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(retryResult, candidatePath);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord retriedCandidate));
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks > exactDeadlineTicks);
        Assert.Equal(2UL, retriedCandidate.Validation.ChallengeSendCount);
    }
}

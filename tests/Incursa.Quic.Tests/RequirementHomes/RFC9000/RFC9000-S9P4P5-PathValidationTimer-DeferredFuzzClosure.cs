// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S9P4P5_PathValidationTimer_DeferredFuzzClosure
{
    [Theory]
    [InlineData("203.0.113.51", 443, "203.0.113.61", 443, 20)]
    [InlineData("203.0.113.52", 4433, "203.0.113.62", 8443, 200)]
    [InlineData("2001:db8::51", 443, "2001:db8::61", 443, 2_000)]
    [Requirement("RFC9000-S9-4-P5-S2-R01")]
    [Requirement("RFC9000-S9-4-P5-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PathValidationTimerFuzz_ArmsSeparateTimerAndCancelsItOnMatchingResponse(
        string activeAddress,
        int activePort,
        string candidateAddress,
        int candidatePort,
        long observedAtTicks)
    {
        QuicConnectionPathIdentity activePath = new(activeAddress, RemotePort: activePort);
        QuicConnectionPathIdentity candidatePath = new(candidateAddress, RemotePort: candidatePort);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);

        QuicConnectionTransitionResult startResult = QuicS8P2PathValidationTestSupport.StartCandidatePath(
            runtime,
            candidatePath,
            observedAtTicks);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            startResult,
            candidatePath,
            runtime: runtime);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord candidate));
        Assert.True(candidate.Validation.ChallengeSentAtTicks.HasValue);
        Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Equal(candidate.Validation.ValidationDeadlineTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));
        Assert.Null(runtime.SendRuntime.LossDetectionDeadlineMicros);
        Assert.True(candidate.Validation.ValidationDeadlineTicks.Value > candidate.Validation.ChallengeSentAtTicks.Value);

        long responseTicks = candidate.Validation.ValidationDeadlineTicks.Value - 1;
        QuicConnectionTransitionResult responseResult = runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(
                ObservedAtTicks: responseTicks,
                candidatePath),
            nowTicks: responseTicks);

        Assert.True(responseResult.StateChanged);
        Assert.Contains(responseResult.Effects, effect =>
            effect is QuicConnectionCancelTimerEffect cancel
            && cancel.TimerKind == QuicConnectionTimerKind.PathValidation);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));
    }

    [Theory]
    [InlineData("203.0.113.71", 443, "203.0.113.81", 443, 30)]
    [InlineData("203.0.113.72", 443, "203.0.113.82", 9443, 300)]
    [InlineData("2001:db8::72", 443, "2001:db8::82", 443, 3_000)]
    [Requirement("RFC9000-S9-4-P5-S3-R01")]
    [Requirement("RFC9000-S9-4-P5-S4-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PathValidationRetryFuzz_RetransmitsChallengeAndDoesNotShortenTimer(
        string activeAddress,
        int activePort,
        string candidateAddress,
        int candidatePort,
        long observedAtTicks)
    {
        QuicConnectionPathIdentity activePath = new(activeAddress, RemotePort: activePort);
        QuicConnectionPathIdentity candidatePath = new(candidateAddress, RemotePort: candidatePort);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);

        Assert.True(QuicS8P2PathValidationTestSupport.StartCandidatePath(
            runtime,
            candidatePath,
            observedAtTicks).StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord initialCandidate));
        Assert.True(initialCandidate.Validation.ChallengeSentAtTicks.HasValue);
        Assert.True(initialCandidate.Validation.ValidationDeadlineTicks.HasValue);

        long initialDeadlineTicks = initialCandidate.Validation.ValidationDeadlineTicks.Value;
        long initialIntervalTicks = initialDeadlineTicks - initialCandidate.Validation.ChallengeSentAtTicks.Value;
        ulong initialTimerGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);
        byte[] initialChallengePayload = initialCandidate.Validation.ChallengePayload.ToArray();

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: initialDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                initialTimerGeneration),
            nowTicks: initialDeadlineTicks);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            retryResult,
            candidatePath,
            runtime: runtime);
        Assert.Contains(retryResult.Effects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.PathValidation);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord retriedCandidate));
        Assert.Equal(2UL, retriedCandidate.Validation.ChallengeSendCount);
        Assert.True(retriedCandidate.Validation.ChallengeSentAtTicks.HasValue);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.Value > initialDeadlineTicks);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.Value - retriedCandidate.Validation.ChallengeSentAtTicks.Value >= initialIntervalTicks);
        Assert.False(initialChallengePayload.AsSpan().SequenceEqual(retriedCandidate.Validation.ChallengePayload.Span));
        Assert.True(runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation) > initialTimerGeneration);
    }
}

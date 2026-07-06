// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-2-1-P3-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0435
{
    [Fact]
    [Requirement("RFC9000-S8-2-1-P3-S1-R01")]
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
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(retryResult, candidatePath, runtime: runtime);
    }

    [Fact]
    [Requirement("RFC9000-S8-2-1-P3-S1-R01")]
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
    [Requirement("RFC9000-S8-2-1-P3-S1-R01")]
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

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(retryResult, candidatePath, runtime: runtime);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord retriedCandidate));
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks > exactDeadlineTicks);
        Assert.Equal(2UL, retriedCandidate.Validation.ChallengeSendCount);
    }

    [Fact]
    [Requirement("RFC9000-S8-2-1-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PathValidationTimerExpiryLimitsProbeFrequencyToTheArmedDeadline()
    {
        (QuicConnectionPathIdentity CandidatePath, long ObservedAtTicks)[] cases =
        [
            (new QuicConnectionPathIdentity("203.0.113.130", RemotePort: 443), 20),
            (new QuicConnectionPathIdentity("203.0.113.131", RemotePort: 444), 30),
            (new QuicConnectionPathIdentity("203.0.113.132", LocalAddress: "192.0.2.20", RemotePort: 443, LocalPort: 55_555), 40),
        ];

        foreach ((QuicConnectionPathIdentity candidatePath, long observedAtTicks) in cases)
        {
            using QuicConnectionRuntime runtime =
                QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

            QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks);
            Assert.True(runtime.CandidatePaths.TryGetValue(
                candidatePath,
                out QuicConnectionCandidatePathRecord candidate));
            Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);

            long beforeDeadlineTicks = candidate.Validation.ValidationDeadlineTicks.Value - 1;
            QuicConnectionTransitionResult beforeDeadlineResult =
                QuicS8P2PathValidationTestSupport.StartCandidatePath(
                    runtime,
                    candidatePath,
                    observedAtTicks: beforeDeadlineTicks);

            Assert.DoesNotContain(
                beforeDeadlineResult.Effects,
                effect => effect is QuicConnectionSendDatagramEffect send
                    && QuicS8P2PathValidationTestSupport.CountPathChallengeFrames(send.Datagram.Span) > 0);
            Assert.True(runtime.CandidatePaths.TryGetValue(
                candidatePath,
                out QuicConnectionCandidatePathRecord beforeDeadlineCandidate));
            Assert.Equal(1UL, beforeDeadlineCandidate.Validation.ChallengeSendCount);

            ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);
            QuicConnectionTransitionResult atDeadlineResult = runtime.Transition(
                new QuicConnectionTimerExpiredEvent(
                    ObservedAtTicks: candidate.Validation.ValidationDeadlineTicks.Value,
                    QuicConnectionTimerKind.PathValidation,
                    generation),
                nowTicks: candidate.Validation.ValidationDeadlineTicks.Value);

            QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
                atDeadlineResult,
                candidatePath,
                runtime: runtime);
            Assert.True(runtime.CandidatePaths.TryGetValue(
                candidatePath,
                out QuicConnectionCandidatePathRecord retriedCandidate));
            Assert.Equal(2UL, retriedCandidate.Validation.ChallengeSendCount);
            Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks > candidate.Validation.ValidationDeadlineTicks);
        }
    }
}

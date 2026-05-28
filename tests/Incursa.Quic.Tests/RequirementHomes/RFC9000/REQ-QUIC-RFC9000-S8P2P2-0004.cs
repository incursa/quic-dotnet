// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P2P2-0004")]
public sealed class REQ_QUIC_RFC9000_S8P2P2_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitiatorAcceptsMatchingPathResponseOnTheCandidatePath()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.129", RemotePort: 443);

        QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord candidate));

        QuicConnectionTransitionResult responseResult =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathResponse(
                runtime,
                candidatePath,
                candidate.Validation.ChallengePayload.Span,
                packetNumber: 0x60,
                observedAtTicks: 21);

        Assert.True(responseResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(candidatePath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(runtime.CandidatePaths, entry => entry.Key == candidatePath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void InitiatorAcceptsPathResponseForPreviousOutstandingChallengeAfterRetry()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.131", RemotePort: 443);

        QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord initialCandidate));
        Assert.True(initialCandidate.Validation.ValidationDeadlineTicks.HasValue);

        byte[] initialChallenge = initialCandidate.Validation.ChallengePayload.ToArray();
        long retryTicks = initialCandidate.Validation.ValidationDeadlineTicks.Value;
        ulong timerGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                retryTicks,
                QuicConnectionTimerKind.PathValidation,
                timerGeneration),
            nowTicks: retryTicks);

        Assert.Contains(retryResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord retriedCandidate));
        Assert.False(initialChallenge.AsSpan().SequenceEqual(retriedCandidate.Validation.ChallengePayload.Span));
        Assert.True(initialChallenge.AsSpan().SequenceEqual(retriedCandidate.Validation.PreviousChallengePayload.Span));

        QuicConnectionTransitionResult responseResult =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathResponse(
                runtime,
                candidatePath,
                initialChallenge,
                packetNumber: 0x62,
                observedAtTicks: retryTicks + 1);

        Assert.True(responseResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(candidatePath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(runtime.CandidatePaths, entry => entry.Key == candidatePath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InitiatorDoesNotTreatSamePathResponseRuleAsAnEnforcedPeerViolation()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity candidatePath = new("203.0.113.130", RemotePort: 443);

        QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord candidate));

        QuicConnectionTransitionResult responseOnOldPath =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathResponse(
                runtime,
                activePath,
                candidate.Validation.ChallengePayload.Span,
                packetNumber: 0x61,
                observedAtTicks: 21);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord stillPendingCandidate));
        Assert.False(stillPendingCandidate.Validation.IsValidated);
        Assert.False(stillPendingCandidate.Validation.IsAbandoned);
        Assert.DoesNotContain(
            responseOnOldPath.Effects,
            effect => effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == candidatePath);
    }
}

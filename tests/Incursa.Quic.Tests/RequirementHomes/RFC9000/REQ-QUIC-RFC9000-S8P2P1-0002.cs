// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P2P1-0002")]
public sealed class REQ_QUIC_RFC9000_S8P2P1_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialPathValidationDatagramContainsExactlyOnePathChallenge()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.122", RemotePort: 443);

        QuicConnectionTransitionResult result =
            QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(result, candidatePath, runtime: runtime);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RetryPathValidationDatagramDoesNotBundleMultiplePathChallenges()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.123", RemotePort: 443);

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

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(retryResult, candidatePath, runtime: runtime);
    }
}

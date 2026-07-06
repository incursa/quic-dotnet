// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S8P2P1P2_PathChallengeRetry_DeferredFuzzClosure
{
    [Theory]
    [InlineData("203.0.113.151", 443, 20)]
    [InlineData("203.0.113.152", 8443, 200)]
    [InlineData("2001:db8::151", 443, 2_000)]
    [Requirement("RFC9000-S8-2-1-P2-S1-R01")]
    [Requirement("RFC9000-S8-2-1-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PathChallengeRetryFuzz_SendsMultipleChallengesAcrossPacketsButOnePerPacket(
        string candidateAddress,
        int candidatePort,
        long observedAtTicks)
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new(candidateAddress, RemotePort: candidatePort);

        QuicConnectionTransitionResult initialResult =
            QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            initialResult,
            candidatePath,
            runtime: runtime);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord candidate));
        byte[] previousChallengePayload = candidate.Validation.ChallengePayload.ToArray();
        Assert.Equal(1UL, candidate.Validation.ChallengeSendCount);

        for (int retry = 0; retry < 2; retry++)
        {
            Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);
            long deadlineTicks = candidate.Validation.ValidationDeadlineTicks.Value;
            ulong timerGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);

            QuicConnectionTransitionResult retryResult = runtime.Transition(
                new QuicConnectionTimerExpiredEvent(
                    ObservedAtTicks: deadlineTicks,
                    QuicConnectionTimerKind.PathValidation,
                    timerGeneration),
                nowTicks: deadlineTicks);

            QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
                retryResult,
                candidatePath,
                runtime: runtime);
            Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out candidate));
            Assert.Equal((ulong)(retry + 2), candidate.Validation.ChallengeSendCount);
            Assert.False(previousChallengePayload.AsSpan().SequenceEqual(candidate.Validation.ChallengePayload.Span));
            previousChallengePayload = candidate.Validation.ChallengePayload.ToArray();
        }
    }
}

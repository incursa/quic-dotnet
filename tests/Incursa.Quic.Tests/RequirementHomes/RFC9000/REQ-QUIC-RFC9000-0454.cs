// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-2-4-P2-R01")]
public sealed class REQ_QUIC_RFC9000_0454
{
    [Fact]
    [Requirement("RFC9000-S8-2-4-P2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathValidationTimerEventuallyAbandonsAnExpiredCandidate()
    {
        (QuicConnectionRuntime runtime, QuicConnectionPathIdentity candidatePath, long firstDeadlineTicks, ulong firstGeneration) =
            CreatePendingPathValidation();

        QuicConnectionTransitionResult firstRetryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: firstDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                firstGeneration),
            nowTicks: firstDeadlineTicks);

        Assert.Contains(firstRetryResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == candidatePath
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));

        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord firstRetryCandidate));
        Assert.False(firstRetryCandidate.Validation.IsAbandoned);
        Assert.Equal(2UL, firstRetryCandidate.Validation.ChallengeSendCount);
        Assert.True(firstRetryCandidate.Validation.ValidationDeadlineTicks.HasValue);

        long secondDeadlineTicks = firstRetryCandidate.Validation.ValidationDeadlineTicks.Value;
        ulong secondGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);

        QuicConnectionTransitionResult secondRetryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: secondDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                secondGeneration),
            nowTicks: secondDeadlineTicks);

        Assert.Contains(secondRetryResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == candidatePath
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));

        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord secondRetryCandidate));
        Assert.False(secondRetryCandidate.Validation.IsAbandoned);
        Assert.Equal(3UL, secondRetryCandidate.Validation.ChallengeSendCount);
        Assert.True(secondRetryCandidate.Validation.ValidationDeadlineTicks.HasValue);

        long abandonDeadlineTicks = secondRetryCandidate.Validation.ValidationDeadlineTicks.Value;
        ulong abandonGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);

        QuicConnectionTransitionResult abandonResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: abandonDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                abandonGeneration),
            nowTicks: abandonDeadlineTicks);

        Assert.True(abandonResult.StateChanged);
        Assert.DoesNotContain(abandonResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord abandonedCandidate));
        Assert.True(abandonedCandidate.Validation.IsAbandoned);
        Assert.False(abandonedCandidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));
    }

    [Fact]
    [Requirement("RFC9000-S8-2-4-P2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FirstTimerExpiryStillRetriesInsteadOfAbandoningTheCandidate()
    {
        (QuicConnectionRuntime runtime, QuicConnectionPathIdentity candidatePath, long firstDeadlineTicks, ulong firstGeneration) =
            CreatePendingPathValidation();

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: firstDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                firstGeneration),
            nowTicks: firstDeadlineTicks);

        Assert.Contains(retryResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == candidatePath
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord retriedCandidate));
        Assert.False(retriedCandidate.Validation.IsAbandoned);
        Assert.Equal(2UL, retriedCandidate.Validation.ChallengeSendCount);
        Assert.True(retriedCandidate.Validation.ValidationDeadlineTicks.HasValue);
    }

    private static (QuicConnectionRuntime Runtime, QuicConnectionPathIdentity CandidatePath, long DeadlineTicks, ulong TimerGeneration) CreatePendingPathValidation()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.20", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.21", RemotePort: 443);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                activePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 2).StateChanged);

        QuicConnectionTransitionResult startResult = QuicS8P2PathValidationTestSupport.StartCandidatePath(
            runtime,
            candidatePath,
            observedAtTicks: 20);

        Assert.True(startResult.StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord candidate));
        Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);

        return (
            runtime,
            candidatePath,
            candidate.Validation.ValidationDeadlineTicks.Value,
            runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation));
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0026">A liveness or path validation check using PATH_CHALLENGE frames MUST be sent periodically until a matching PATH_RESPONSE frame is received or until there is no remaining need for liveness or path validation checking.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0026")]
public sealed class REQ_QUIC_RFC9000_S13P3_0026
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0026")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathValidationTimerExpiryRetransmitsTheChallengeWithANewPayload()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicConnectionPathIdentity migratedPath = new("203.0.113.90", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                migratedPath,
                datagram),
            nowTicks: 10);

        QuicConnectionSendDatagramEffect firstSend = Assert.Single(
            firstResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        byte[] firstChallengeData = GetPathChallengeData(firstSend.Datagram.Span);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);

        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        long firstValidationDeadlineTicks = candidatePath.Validation.ValidationDeadlineTicks.Value;
        ulong firstGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);
        Assert.Equal(firstValidationDeadlineTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: firstValidationDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                firstGeneration),
            nowTicks: firstValidationDeadlineTicks);

        QuicConnectionSendDatagramEffect retrySend = Assert.Single(
            retryResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        byte[] retryChallengeData = GetPathChallengeData(retrySend.Datagram.Span);

        Assert.Equal(migratedPath, retrySend.PathIdentity);
        Assert.False(firstChallengeData.AsSpan().SequenceEqual(retryChallengeData));
        Assert.True(retryResult.StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord retriedCandidatePath));
        Assert.False(retriedCandidatePath.Validation.IsValidated);
        Assert.False(retriedCandidatePath.Validation.IsAbandoned);
        Assert.Equal(2UL, retriedCandidatePath.Validation.ChallengeSendCount);
        Assert.True(retriedCandidatePath.Validation.ValidationDeadlineTicks.HasValue);
        Assert.NotEqual(firstValidationDeadlineTicks, retriedCandidatePath.Validation.ValidationDeadlineTicks.Value);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);
        Assert.NotEqual(firstGeneration, runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0026")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidatedCandidatePathDoesNotRetransmitAfterTheTimerIsCleared()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicConnectionPathIdentity migratedPath = new("203.0.113.91", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                migratedPath,
                datagram),
            nowTicks: 10);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);

        long validationDeadlineTicks = candidatePath.Validation.ValidationDeadlineTicks.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);
        long validationClearedAtTicks = validationDeadlineTicks > 0 ? validationDeadlineTicks - 1 : 0;

        Assert.True(runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(
                ObservedAtTicks: validationClearedAtTicks,
                migratedPath),
            nowTicks: validationClearedAtTicks).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord validatedPath));
        Assert.True(validatedPath.Validation.IsValidated);
        Assert.Null(validatedPath.Validation.ValidationDeadlineTicks);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: validationDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                generation),
            nowTicks: validationDeadlineTicks);

        Assert.False(timerResult.StateChanged);
        Assert.DoesNotContain(timerResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0026")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AbandonedCandidatePathDoesNotRetransmitAfterTheTimerIsCleared()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicConnectionPathIdentity migratedPath = new("203.0.113.92", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                migratedPath,
                datagram),
            nowTicks: 10);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);

        long validationDeadlineTicks = candidatePath.Validation.ValidationDeadlineTicks.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);
        long abandonmentTicks = validationDeadlineTicks > 0 ? validationDeadlineTicks - 1 : 0;

        Assert.True(runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: abandonmentTicks,
                migratedPath,
                IsAbandoned: true),
            nowTicks: abandonmentTicks).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord abandonedPath));
        Assert.True(abandonedPath.Validation.IsAbandoned);
        Assert.Null(abandonedPath.Validation.ValidationDeadlineTicks);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: validationDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                generation),
            nowTicks: validationDeadlineTicks);

        Assert.False(timerResult.StateChanged);
        Assert.DoesNotContain(timerResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0026")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0027")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PathValidationTimerExpiryRetransmitsDistinctChallengesForRepresentativePaths()
    {
        for (int iteration = 0; iteration < 16; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicConnectionPathIdentity migratedPath = new(
                $"203.0.113.{100 + iteration}",
                RemotePort: 443 + iteration);
            byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize + (iteration % 3)];
            long observedAtTicks = 100 + (iteration * 10);

            QuicConnectionTransitionResult firstResult = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: observedAtTicks,
                    migratedPath,
                    datagram),
                nowTicks: observedAtTicks);

            QuicConnectionSendDatagramEffect firstSend = Assert.Single(
                firstResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
            byte[] firstChallengeData = GetPathChallengeData(firstSend.Datagram.Span);

            Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
            long validationDeadlineTicks = candidatePath.Validation.ValidationDeadlineTicks.Value;
            ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);

            QuicConnectionTransitionResult retryResult = runtime.Transition(
                new QuicConnectionTimerExpiredEvent(
                    ObservedAtTicks: validationDeadlineTicks,
                    QuicConnectionTimerKind.PathValidation,
                    generation),
                nowTicks: validationDeadlineTicks);

            QuicConnectionSendDatagramEffect retrySend = Assert.Single(
                retryResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
            byte[] retryChallengeData = GetPathChallengeData(retrySend.Datagram.Span);

            Assert.Equal(migratedPath, retrySend.PathIdentity);
            Assert.False(firstChallengeData.AsSpan().SequenceEqual(retryChallengeData));
            Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord retriedCandidatePath));
            Assert.False(retriedCandidatePath.Validation.IsValidated);
            Assert.False(retriedCandidatePath.Validation.IsAbandoned);
            Assert.Equal(2UL, retriedCandidatePath.Validation.ChallengeSendCount);
            Assert.True(retriedCandidatePath.Validation.ValidationDeadlineTicks.HasValue);
        }
    }

    private static byte[] GetPathChallengeData(ReadOnlySpan<byte> datagram)
    {
        Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(
            datagram,
            out QuicPathChallengeFrame parsedChallenge,
            out int bytesConsumed));
        Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, bytesConsumed);

        ReadOnlySpan<byte> remainingPayload = datagram[bytesConsumed..];
        Assert.True(remainingPayload.SequenceEqual(new byte[remainingPayload.Length]));
        return parsedChallenge.Data.ToArray();
    }
}

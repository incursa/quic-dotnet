namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0010")]
public sealed class REQ_QUIC_RFC9000_S9P3_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AStaleCandidatePathCanBeAbandonedAfterTheConnectionHasMovedToAnotherValidatedAddress()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.109", RemotePort: 443);
        QuicConnectionPathIdentity staleCandidatePath = new("203.0.113.110", RemotePort: 443);
        QuicConnectionPathIdentity promotedPath = new("203.0.113.111", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                staleCandidatePath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                promotedPath,
                datagram),
            nowTicks: 30).StateChanged);

        QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            promotedPath,
            observedAtTicks: 40);

        QuicConnectionTransitionResult abandonResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 50,
                staleCandidatePath,
                IsAbandoned: true),
            nowTicks: 50);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(promotedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(promotedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.CandidatePaths.TryGetValue(staleCandidatePath, out QuicConnectionCandidatePathRecord abandonedCandidatePath));
        Assert.False(abandonedCandidatePath.Validation.IsValidated);
        Assert.True(abandonedCandidatePath.Validation.IsAbandoned);
        Assert.Null(abandonedCandidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(abandonResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PendingValidationForOtherAddressesContinuesBeforeNonProbingTrafficMovesToANewAddress()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity firstCandidatePath = new("203.0.113.112", RemotePort: 443);
        QuicConnectionPathIdentity secondCandidatePath = new("203.0.113.113", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                firstCandidatePath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult secondCandidateResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                secondCandidatePath,
                datagram),
            nowTicks: 30);

        Assert.True(secondCandidateResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(activePath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.CandidatePaths.TryGetValue(firstCandidatePath, out QuicConnectionCandidatePathRecord firstCandidate));
        Assert.True(runtime.CandidatePaths.TryGetValue(secondCandidatePath, out QuicConnectionCandidatePathRecord secondCandidate));
        Assert.False(firstCandidate.Validation.IsValidated);
        Assert.False(firstCandidate.Validation.IsAbandoned);
        Assert.True(firstCandidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.False(secondCandidate.Validation.IsValidated);
        Assert.False(secondCandidate.Validation.IsAbandoned);
        Assert.True(secondCandidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.DoesNotContain(secondCandidateResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ChangingToAnotherValidatedAddressDoesNotAutomaticallyAbandonOtherPendingPathValidation()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity staleCandidatePath = new("203.0.113.114", RemotePort: 443);
        QuicConnectionPathIdentity promotedPath = new("203.0.113.115", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                staleCandidatePath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                promotedPath,
                datagram),
            nowTicks: 30).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            promotedPath,
            observedAtTicks: 40);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(promotedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(promotedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(activePath));
        Assert.True(runtime.CandidatePaths.TryGetValue(staleCandidatePath, out QuicConnectionCandidatePathRecord staleCandidatePathRecord));
        Assert.False(staleCandidatePathRecord.Validation.IsValidated);
        Assert.False(staleCandidatePathRecord.Validation.IsAbandoned);
        Assert.True(staleCandidatePathRecord.Validation.ValidationDeadlineTicks.HasValue);
        Assert.DoesNotContain(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == staleCandidatePath);
    }
}

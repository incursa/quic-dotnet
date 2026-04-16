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
}

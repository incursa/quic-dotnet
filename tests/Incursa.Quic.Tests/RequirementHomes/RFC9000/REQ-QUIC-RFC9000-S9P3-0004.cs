namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0004")]
public sealed class REQ_QUIC_RFC9000_S9P3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecentlyValidatedPeerAddressCanBypassAnotherValidationChallenge()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.104", RemotePort: 443);
        QuicConnectionPathIdentity firstValidatedPath = new("203.0.113.105", RemotePort: 443);
        QuicConnectionPathIdentity secondValidatedPath = new("203.0.113.106", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                firstValidatedPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            firstValidatedPath,
            observedAtTicks: 30);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                secondValidatedPath,
                datagram),
            nowTicks: 40).StateChanged);

        QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            secondValidatedPath,
            observedAtTicks: 50);

        Assert.True(runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 60,
                TransportFlags: QuicConnectionTransportState.DisableActiveMigration),
            nowTicks: 60).StateChanged);

        QuicConnectionTransitionResult reuseResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 70,
                firstValidatedPath,
                datagram),
            nowTicks: 70);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(secondValidatedPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(firstValidatedPath, out QuicConnectionCandidatePathRecord reusedCandidatePath));
        Assert.True(reusedCandidatePath.Validation.IsValidated);
        Assert.False(reusedCandidatePath.Validation.IsAbandoned);
        Assert.Equal(0UL, reusedCandidatePath.Validation.ChallengeSendCount);
        Assert.Null(reusedCandidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(reuseResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }
}

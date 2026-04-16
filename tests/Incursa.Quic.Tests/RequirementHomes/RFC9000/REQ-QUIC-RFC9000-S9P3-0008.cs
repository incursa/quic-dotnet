namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0008")]
public sealed class REQ_QUIC_RFC9000_S9P3_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedMigrationPromotesTheMigratedPathBeforeTheNextReplyPacket()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.74", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.75", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PathValidationMustCompleteBeforeReplyPacketsSwitchToTheMigratedAddress()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.76", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.77", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult replyResult = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 30,
                QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
            nowTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Contains(replyResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == activePath);
        Assert.DoesNotContain(replyResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}

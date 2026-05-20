namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P5-0004")]
public sealed class REQ_QUIC_RFC9000_S9P5_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedMigrationMayKeepTheSameLocalAddressWhenThePeerSourceAddressChanges()
    {
        AssertValidatedMigrationPromotesWithSameLocalAddress(
            new QuicConnectionPathIdentity("203.0.113.180", "198.51.100.180", RemotePort: 443, LocalPort: 61234),
            new QuicConnectionPathIdentity("203.0.113.181", "198.51.100.180", RemotePort: 443, LocalPort: 61234));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidatedMigrationDoesNotPromoteBeforeHandshakeTranscriptCompletion()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.182", "198.51.100.182", RemotePort: 443, LocalPort: 61234);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.183", "198.51.100.182", RemotePort: 443, LocalPort: 61234);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                activePath,
                datagram),
            nowTicks: 10).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.DoesNotContain(validationResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0008")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ValidatedMigrationKeepsTheSameLocalAddressAtTheMaximumRemotePortBoundary()
    {
        AssertValidatedMigrationPromotesWithSameLocalAddress(
            new QuicConnectionPathIdentity("203.0.113.184", "198.51.100.184", RemotePort: 443, LocalPort: 61234),
            new QuicConnectionPathIdentity("203.0.113.185", "198.51.100.184", RemotePort: ushort.MaxValue, LocalPort: 61234));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task PeerAddressRebindingWithoutAnUnusedPeerConnectionIdCanReuseTheCurrentAddressPairConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity originalPath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity reboundPath = new(
            "203.0.113.244",
            originalPath.LocalAddress,
            RemotePort: 443,
            originalPath.LocalPort);
        byte[] originalPairConnectionId = [0x95, 0x96, 0x97, 0x98];

        await REQ_QUIC_RFC9000_S5P1P2_0006.BindPeerConnectionIdToCurrentPath(runtime, originalPairConnectionId);

        QuicConnectionTransitionResult validationResult =
            REQ_QUIC_RFC9000_S5P1P2_0006.ValidateMigratedPath(runtime, reboundPath);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(reboundPath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(runtime.CandidatePaths.Keys, path => path.Equals(reboundPath));
        Assert.Contains(
            validationResult.Effects,
            effect => effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == reboundPath);

        QuicConnectionSendDatagramEffect sendAfterPeerRebinding =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        Assert.Equal(reboundPath, sendAfterPeerRebinding.PathIdentity);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramOpensWithDestination(
            runtime,
            sendAfterPeerRebinding.Datagram,
            originalPairConnectionId);
    }

    private static void AssertValidatedMigrationPromotesWithSameLocalAddress(
        QuicConnectionPathIdentity activePath,
        QuicConnectionPathIdentity migratedPath)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(activePath.LocalAddress, runtime.ActivePath.Value.Identity.LocalAddress);
        Assert.Equal(activePath.LocalPort, runtime.ActivePath.Value.Identity.LocalPort);
        Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P2-0004")]
public sealed class REQ_QUIC_RFC9000_S9P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PortOnlyPeerAddressChangesRetainThePathRecoveryState()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.60",
            LocalAddress: "198.51.100.60",
            RemotePort: 443,
            LocalPort: 61284);
        QuicConnectionPathIdentity portOnlyPath = new(
            RemoteAddress: "203.0.113.60",
            LocalAddress: "198.51.100.60",
            RemotePort: 8443,
            LocalPort: 61284);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        QuicPathMigrationRecoverySnapshot dirty = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                portOnlyPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            portOnlyPath,
            observedAtTicks: 30);

        QuicPathMigrationRecoverySnapshot afterPromotion = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.Equal(dirty, afterPromotion);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(portOnlyPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == portOnlyPath
            && promote.RestoreSavedState);
    }
}

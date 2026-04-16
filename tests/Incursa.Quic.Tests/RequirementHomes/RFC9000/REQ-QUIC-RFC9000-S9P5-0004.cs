namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P5-0004")]
public sealed class REQ_QUIC_RFC9000_S9P5_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedMigrationMayKeepTheSameLocalAddressWhenThePeerSourceAddressChanges()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.180", "198.51.100.180", RemotePort: 443, LocalPort: 61234);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.181", "198.51.100.180", RemotePort: 443, LocalPort: 61234);
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

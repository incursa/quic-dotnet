namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0001")]
public sealed class REQ_QUIC_RFC9000_S9P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedMigrationRoutesLocalClosePacketsToTheMigratedAddress()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.70", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.71", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 40,
                QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
            nowTicks: 40);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
        Assert.Contains(closeResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath);
    }
}

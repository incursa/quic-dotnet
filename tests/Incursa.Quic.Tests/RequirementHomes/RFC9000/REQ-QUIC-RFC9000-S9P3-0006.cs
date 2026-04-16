namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0006")]
public sealed class REQ_QUIC_RFC9000_S9P3_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedMigrationRoutesConnectionCloseRepliesToTheMigratedAddress()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.72", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.73", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20).StateChanged);

        QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        QuicConnectionTransitionResult replyResult = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 40,
                QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
            nowTicks: 40);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(replyResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath);
    }
}

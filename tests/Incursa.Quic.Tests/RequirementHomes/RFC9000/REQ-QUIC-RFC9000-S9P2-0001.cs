namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P2-0001")]
public sealed class REQ_QUIC_RFC9000_S9P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReplyTrafficStaysOnTheOriginalPathWhileValidationIsPending()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.30",
            LocalAddress: "198.51.100.30",
            RemotePort: 443,
            LocalPort: 61254);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.30",
            LocalAddress: "198.51.100.31",
            RemotePort: 443,
            LocalPort: 61255);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
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
        Assert.DoesNotContain(replyResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath);
    }
}

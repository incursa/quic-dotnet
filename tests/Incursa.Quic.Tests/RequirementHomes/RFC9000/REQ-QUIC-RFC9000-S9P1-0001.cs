namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P1-0001")]
public sealed class REQ_QUIC_RFC9000_S9P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewLocalAddressIsProbedBeforeTheConnectionMigrates()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.10",
            LocalAddress: "198.51.100.10",
            RemotePort: 443,
            LocalPort: 61234);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.10",
            LocalAddress: "198.51.100.11",
            RemotePort: 443,
            LocalPort: 61235);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Contains(receiveResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(migratedPath.LocalAddress, runtime.ActivePath.Value.Identity.LocalAddress);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }
}

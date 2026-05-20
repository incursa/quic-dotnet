namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P1-0002")]
public sealed class REQ_QUIC_RFC9000_S9P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnvalidatedNewLocalAddressDoesNotReplaceTheActivePath()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.20",
            LocalAddress: "198.51.100.20",
            RemotePort: 443,
            LocalPort: 61244);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.20",
            LocalAddress: "198.51.100.21",
            RemotePort: 443,
            LocalPort: 61245);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.AddUnusedPeerConnectionId(runtime);
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
        Assert.DoesNotContain(receiveResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void UnvalidatedNewLocalAddressAtTheMaximumPortBoundaryStillDoesNotReplaceTheActivePath()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.20",
            LocalAddress: "198.51.100.20",
            RemotePort: 443,
            LocalPort: 61244);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.20",
            LocalAddress: "198.51.100.21",
            RemotePort: 443,
            LocalPort: ushort.MaxValue);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.AddUnusedPeerConnectionId(runtime);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                migratedPath,
                datagram),
            nowTicks: 30);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            receiveResult,
            migratedPath,
            runtime: runtime);
        Assert.DoesNotContain(receiveResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}

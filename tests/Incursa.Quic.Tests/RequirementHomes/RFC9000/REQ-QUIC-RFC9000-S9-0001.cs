namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9-0001")]
public sealed class REQ_QUIC_RFC9000_S9_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientDoesNotPromoteANewLocalAddressBeforeHandshakeConfirmation()
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
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePathBeforeHandshakeConfirmation(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.False(runtime.HandshakeConfirmed);

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
        Assert.DoesNotContain(receiveResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == migratedPath);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out candidatePath));
        Assert.True(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == migratedPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9-0008")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientDelaysPromotingAPrevalidatedPathUntilAfterHandshakeConfirmation()
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
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.False(runtime.HandshakeConfirmed);

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.DoesNotContain(receiveResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == migratedPath);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out candidatePath));
        Assert.True(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.DoesNotContain(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == migratedPath);

        QuicConnectionTransitionResult handshakeResult = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 40);

        Assert.True(handshakeResult.StateChanged);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out candidatePath));
        Assert.True(candidatePath.Validation.IsValidated);
        Assert.DoesNotContain(handshakeResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == migratedPath);

        QuicConnectionTransitionResult postHandshakeReceiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 50,
                migratedPath,
                datagram),
            nowTicks: 50);

        Assert.True(postHandshakeReceiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(migratedPath));
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(migratedPath));
        Assert.Contains(postHandshakeReceiveResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == migratedPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientPromotesANewLocalAddressAfterHandshakeConfirmation()
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
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.HandshakeConfirmed);

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
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            receiveResult,
            migratedPath,
            runtime: runtime);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(migratedPath));
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(migratedPath));
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == migratedPath
            && !promoteActivePathEffect.RestoreSavedState);
    }
}
